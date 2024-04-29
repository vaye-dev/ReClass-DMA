#include "vmmdll.h"
#include "nativecore/ReClassNET_Plugin.hpp"
#include <algorithm>
#include <cstdint>
#include <vector>
#include <filesystem>
#include <sstream>
#include <string>

static VMM_HANDLE _hVmm = NULL;

static const bool _hasMemMap = std::filesystem::exists("mmap.txt");
static size_t _dtbFileSize = 0x80000;
static size_t _size = 0;
static DWORD64 _base = 0;

struct DTBINFO
{
	DWORD index;
	DWORD pid;
	DWORD64 dtb;
	DWORD64 addr;
	std::string name;
};

inline VOID AddFileCallback(HANDLE handle, LPCSTR fileName, ULONG64 fileSize, VMMDLL_VFS_FILELIST_EXINFO* exInfo) {
	if (!strcmp("dtb.txt", fileName))
		_dtbFileSize = fileSize;
}

bool UpdateDirectoryTableBase(RC_Pointer handle, const std::string& name) {
	VMMDLL_MAP_MODULEENTRY* moduleEntry{ };
	if (VMMDLL_Map_GetModuleFromNameU(_hVmm, (DWORD)handle, name.c_str(), &moduleEntry, VMMDLL_MODULE_FLAG_NORMAL))
		return true;

	if (!VMMDLL_InitializePlugins(_hVmm)) {
		return false;
	}

	Sleep(1000);

	while (true) {
		unsigned char ppData[0x3]{ };
		DWORD i{ };

		auto status = VMMDLL_VfsReadU(_hVmm, "\\misc\\procinfo\\progress_percent.txt", ppData, 0x3, &i, 0);
		if (status == VMMDLL_STATUS_SUCCESS && std::atoi(reinterpret_cast<char*>(ppData)) == 100)
			break;

		Sleep(100);
	}

	VMMDLL_VFS_FILELIST2 vfsFileList{ };
	vfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
	vfsFileList.h = _hVmm;
	vfsFileList.pfnAddDirectory = nullptr;
	vfsFileList.pfnAddFile = AddFileCallback;

	if (!VMMDLL_VfsListU(_hVmm, "\\misc\\procinfo\\", &vfsFileList))
		return false;

	auto dtbData = new unsigned char[_dtbFileSize];
	DWORD i{ };

	auto status = VMMDLL_VfsReadU(_hVmm, "\\misc\\procinfo\\dtb.txt", dtbData, _dtbFileSize - 1, &i, NULL);
	if (status != VMMDLL_STATUS_SUCCESS) {
		delete[] dtbData;
		return false;
	}

	std::vector<DTBINFO> possibleDTBS{ };
	std::istringstream dtb_data_ss(reinterpret_cast<char*>(dtbData));
	std::string currentLine{ };

	while (std::getline(dtb_data_ss, currentLine)) {
		DTBINFO info{ };

		std::istringstream ss(currentLine);
		ss >> std::hex >> info.index >> std::dec >> info.pid >> std::hex >> info.dtb >> info.addr >> info.name;

		if (name.find(info.name) != std::string::npos || info.pid == 0)
			possibleDTBS.push_back(info);
	}

	for (size_t i = 0; i < possibleDTBS.size(); i++) {
		VMMDLL_ConfigSet(_hVmm, VMMDLL_OPT_PROCESS_DTB | (DWORD)handle, possibleDTBS[i].dtb);

		if (VMMDLL_Map_GetModuleFromNameU(_hVmm, (DWORD)handle, name.c_str(), &moduleEntry, VMMDLL_MODULE_FLAG_NORMAL)) {
			_base = moduleEntry->vaBase;
			_size = moduleEntry->cbImageSize;
			VMMDLL_MemFree(moduleEntry);
			return true;
		}
	}

	return false;
}

extern "C" void RC_CallConv EnumerateProcesses(EnumerateProcessCallback callbackProcess) {
	if (callbackProcess == nullptr) {
		return;
	}

	if (!_hVmm) {
		if (_hasMemMap)
		{
			LPCSTR argv[] = { "-v", "-device", "fpga", "-memmap", "mmap.txt", "-waitinitialize" };
			_hVmm = VMMDLL_Initialize(6, argv);
		}
		else
		{
			LPCSTR argv[] = { "-v", "-device", "fpga", "-waitinitialize" };
			_hVmm = VMMDLL_Initialize(4, argv);
		}

		if (!_hVmm) {
			MessageBoxA(0, "FAIL: VMMDLL_Initialize", 0, MB_OK | MB_ICONERROR);

			ExitProcess(-1);
		}
	}

	BOOL result;
	ULONG64 cPIDs = 0;
	DWORD i, * pPIDs = NULL;

	result =
		VMMDLL_PidList(_hVmm, NULL, &cPIDs) && (pPIDs = (DWORD*)LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD))) && VMMDLL_PidList(_hVmm, pPIDs, &cPIDs);

	if (!result) {
		LocalFree(pPIDs);
		return;
	}

	for (i = 0; i < cPIDs; i++) {
		DWORD dwPID = pPIDs[i];

		VMMDLL_PROCESS_INFORMATION info;
		SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
		ZeroMemory(&info, cbInfo);
		info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
		info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

		result = VMMDLL_ProcessGetInformation(_hVmm, dwPID, &info, &cbInfo);

		if (result) {
			EnumerateProcessData data = {};
			data.Id = dwPID;
			MultiByteToUnicode(info.szNameLong, data.Name, PATH_MAXIMUM_LENGTH);

			LPSTR szPathUser = VMMDLL_ProcessGetInformationString(_hVmm, dwPID, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);

			if (szPathUser) {
				MultiByteToUnicode(szPathUser, data.Path, PATH_MAXIMUM_LENGTH);
			}

			callbackProcess(&data);
		}
	}

	LocalFree(pPIDs);
}

extern "C" void RC_CallConv EnumerateRemoteSectionsAndModules(RC_Pointer handle, EnumerateRemoteSectionsCallback callbackSection,
	EnumerateRemoteModulesCallback callbackModule) {
	if (callbackSection == nullptr && callbackModule == nullptr) {
		return;
	}

	BOOL result;
	DWORD dwPID = (DWORD)handle;
	ULONG64 i, j;

	DWORD cMemMapEntries = 0;
	PVMMDLL_MAP_PTE pMemMapEntries = NULL;
	PVMMDLL_MAP_PTEENTRY memMapEntry = NULL;

	result = VMMDLL_Map_GetPte(_hVmm, dwPID, TRUE, &pMemMapEntries);

	if (!result) {
		MessageBoxA(0, "FAIL: VMMDLL_Map_GetPte", 0, MB_OK | MB_ICONERROR);

		ExitProcess(-1);
	}


	std::vector< EnumerateRemoteSectionData > sections;

	for (i = 0; i < pMemMapEntries->cMap; i++) {
		memMapEntry = &pMemMapEntries->pMap[i];

		EnumerateRemoteSectionData section = {};
		section.BaseAddress = (RC_Pointer)memMapEntry->vaBase;
		section.Size = memMapEntry->cPages << 12;

		section.Protection = SectionProtection::NoAccess;
		section.Category = SectionCategory::Unknown;

		if (memMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NS)
			section.Protection |= SectionProtection::Read;
		if (memMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_W)
			section.Protection |= SectionProtection::Write;
		if (!(memMapEntry->fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX))
			section.Protection |= SectionProtection::Execute;

		if (memMapEntry->wszText[0]) {
			if ((memMapEntry->wszText[0] == 'H' && memMapEntry->wszText[1] == 'E' && memMapEntry->wszText[2] == 'A' &&
				memMapEntry->wszText[3] == 'P') ||
				(memMapEntry->wszText[0] == '[' && memMapEntry->wszText[1] == 'H' && memMapEntry->wszText[2] == 'E' &&
					memMapEntry->wszText[3] == 'A' && memMapEntry->wszText[4] == 'P')) {
				section.Type = SectionType::Private;

			}
			else {
				section.Type = SectionType::Image;

				LPWSTR w = memMapEntry->wszText;
				char c[64] = { 0 };
				wcstombs(c, w, wcslen(w));

				MultiByteToUnicode(c, section.ModulePath, PATH_MAXIMUM_LENGTH);
			}
		}
		else {
			section.Type = SectionType::Mapped;
		}

		sections.push_back(std::move(section));
	}
	VMMDLL_MemFree(pMemMapEntries);

	DWORD cModuleEntries = 0;
	PVMMDLL_MAP_MODULE pModuleEntries = NULL;

	result = VMMDLL_Map_GetModule(_hVmm, dwPID, &pModuleEntries, NULL);

	if (!result) {
		MessageBoxA(0, "FAIL: VMMDLL_Map_GetModule", 0, MB_OK | MB_ICONERROR);

		ExitProcess(-1);
	}

	for (i = 0; i < pModuleEntries->cMap; i++) {

		EnumerateRemoteModuleData data = {};
		data.BaseAddress = (RC_Pointer)pModuleEntries->pMap[i].vaBase;
		data.Size = (RC_Size)pModuleEntries->pMap[i].cbImageSize;

		LPWSTR ws = pModuleEntries->pMap[i].wszText;
		char cs[64] = { 0 };
		wcstombs(cs, ws, wcslen(ws));

		MultiByteToUnicode(cs, data.Path, PATH_MAXIMUM_LENGTH);

		callbackModule(&data);

		// !!!!!!!!!
		// <warning>
		// this code crashes some processes, possibly a bug with vmm.dll
		DWORD cSections = 0;
		PIMAGE_SECTION_HEADER sectionEntry, pSections = NULL;

		result = VMMDLL_ProcessGetSections(_hVmm, dwPID, pModuleEntries->pMap[i].wszText, NULL, 0, &cSections) && cSections &&
			(pSections = (PIMAGE_SECTION_HEADER)LocalAlloc(0, cSections * sizeof(IMAGE_SECTION_HEADER))) &&
			VMMDLL_ProcessGetSections(_hVmm, dwPID, pModuleEntries->pMap[i].wszText, pSections, cSections, &cSections);

		if (result) {
			for (j = 0; j < cSections; j++) {
				sectionEntry = pSections + j;

				auto it =
					std::lower_bound(std::begin(sections), std::end(sections), reinterpret_cast<LPVOID>(pModuleEntries->pMap[i].vaBase),
						[&sections](const auto& lhs, const LPVOID& rhs) { return lhs.BaseAddress < rhs; });

				auto sectionAddress = (uintptr_t)(pModuleEntries->pMap[i].vaBase + sectionEntry->VirtualAddress);

				for (auto k = it; k != std::end(sections); ++k) {
					uintptr_t start = (uintptr_t)k->BaseAddress;
					uintptr_t end = (uintptr_t)k->BaseAddress + k->Size;

					if (sectionAddress >= start && sectionAddress < end) {
						// Copy the name because it is not null padded.
						char buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
						std::memcpy(buffer, sectionEntry->Name, IMAGE_SIZEOF_SHORT_NAME);

						if (std::strcmp(buffer, ".text") == 0 || std::strcmp(buffer, "code") == 0) {
							k->Category = SectionCategory::CODE;
						}
						else if (std::strcmp(buffer, ".data") == 0 || std::strcmp(buffer, "data") == 0 ||
							std::strcmp(buffer, ".rdata") == 0 || std::strcmp(buffer, ".idata") == 0) {
							k->Category = SectionCategory::DATA;
						}
						MultiByteToUnicode(buffer, k->Name, IMAGE_SIZEOF_SHORT_NAME);
					}
				}
			}
		}
		LocalFree(pSections);
	}
	VMMDLL_MemFree(pModuleEntries);


	if (callbackSection != nullptr) {
		for (auto&& section : sections) {
			callbackSection(&section);
		}
	}
}

extern "C" RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess desiredAccess) {
	return id;
}

extern "C" bool RC_CallConv IsProcessValid(RC_Pointer handle) {
	VMMDLL_PROCESS_INFORMATION info;
	SIZE_T cbInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
	ZeroMemory(&info, cbInfo);
	info.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
	info.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;

	if (VMMDLL_ProcessGetInformation(_hVmm, (DWORD)handle, &info, &cbInfo) && UpdateDirectoryTableBase(handle, info.szNameLong) ) {
		return true;
	}

	return false;
}

extern "C" void RC_CallConv CloseRemoteProcess(RC_Pointer handle)
{
	if (_hVmm)
	{
		VMMDLL_Close(_hVmm);
		_hVmm = NULL;
	}
}

extern "C" bool RC_CallConv ReadRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size) {
	buffer = reinterpret_cast<RC_Pointer>(reinterpret_cast<uintptr_t>(buffer) + offset);

	if (VMMDLL_MemRead(_hVmm, (DWORD)handle, (ULONG64)address, (PBYTE)buffer, size)) {
		return true;
	}

	return false;
}

extern "C" bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	// Mem Writing Not Supported!
	return false;
}

////////////////////////////////////////
////////////////////////////////////////
// Remote debugging is not supported
////////////////////////////////////////
////////////////////////////////////////

extern "C" void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action) {
}

extern "C" bool RC_CallConv AttachDebuggerToProcess(RC_Pointer id) {
	return false;
}

extern "C" void RC_CallConv DetachDebuggerFromProcess(RC_Pointer id) {
}

extern "C" bool RC_CallConv AwaitDebugEvent(DebugEvent * evt, int timeoutInMilliseconds) {
	return false;
}

extern "C" void RC_CallConv HandleDebugEvent(DebugEvent * evt) {
}

extern "C" bool RC_CallConv SetHardwareBreakpoint(RC_Pointer id, RC_Pointer address, HardwareBreakpointRegister reg, HardwareBreakpointTrigger type,
	HardwareBreakpointSize size, bool set) {
	return false;
}
