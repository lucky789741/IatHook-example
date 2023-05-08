#include "logger.hpp"
#include "hook.hpp"

pFnGetCurrentProcess originalFunction = nullptr;

HANDLE WINAPI HOOK::MyGetCurrentProcess()
{
	return 0;
}

void HOOK::IatHookGetCurrentProcess()
{
	Logger::getInstance().print("開始Hook GetCurrentProcess");
	PVOID pHookAddress = nullptr;
	HMODULE hModKernel32 = GetModuleHandleA("kernel32.dll");
	if (hModKernel32 == nullptr)
	{
		Logger::getInstance().print("GetModuleHandleA(\"kernel32.dll\")失敗");
		return;
	}
	pHookAddress = GetProcAddress(hModKernel32, "GetCurrentProcess");
	if (nullptr == pHookAddress)
	{
		Logger::getInstance().print("獲取GetCurrentProcess地址失敗");
		return;
	}
	Logger::getInstance().print("保存原始GetCurrentProcess指標");
	originalFunction = (pFnGetCurrentProcess)pHookAddress;

	//尋找IAT
	HMODULE  hModImageBase = GetModuleHandle(NULL);//獲得ImageBase
	if (hModImageBase == NULL)
	{
		Logger::getInstance().print("GetModuleHandle(NULL)失敗");
		return;
	}
	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)hModImageBase; //獲得Dos headear
	PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModImageBase + pDosHead->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	//獲得導入表
	DWORD dwNum = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwNum);
	if (pImportDescriptor == NULL)
	{
		Logger::getInstance().print("獲得導入表失敗");
		return;
	}

	PIMAGE_IMPORT_BY_NAME functionName;
	//遍歷導入表
	while (pImportDescriptor->Name!=NULL)
	{
		PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
		originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModImageBase + pImportDescriptor->OriginalFirstThunk);
		firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModImageBase + pImportDescriptor->FirstThunk);
		while (originalFirstThunk->u1.AddressOfData!=NULL && firstThunk->u1.Function != NULL)
		{
			functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)hModImageBase + originalFirstThunk->u1.AddressOfData);

			//找地址
			if ((DWORD_PTR)originalFunction == firstThunk->u1.Function)
			{
				PDWORD_PTR function = &firstThunk->u1.Function;
				Logger::getInstance().print((std::string)"Hook! Name:"+functionName->Name+(std::string)"\nAddress:"+Logger::AddressToHexString(function));
				DWORD oldProtect;
				VirtualProtect(function, sizeof(*function), PAGE_EXECUTE_READWRITE, &oldProtect);
				*function = (DWORD_PTR)MyGetCurrentProcess;
			}
			++originalFirstThunk;
			++firstThunk;
		}
		++pImportDescriptor;
	}

}

void HOOK::IatUnHookGetCurrentProcess()
{
	if (originalFunction == nullptr)
	{
		Logger::getInstance().print("無法UnHook因為沒有被Hook");
		return;
	}
	Logger::getInstance().print("開始UnHook GetCurrentProcess");

	//尋找IAT
	HMODULE  hModImageBase = GetModuleHandle(NULL);//獲得ImageBase
	if (hModImageBase == NULL)
	{
		Logger::getInstance().print("GetModuleHandle(NULL)失敗");
		return;
	}
	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)hModImageBase; //獲得Dos headear
	PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModImageBase + pDosHead->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	//獲得導入表
	DWORD dwNum = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwNum);
	if (pImportDescriptor == NULL)
	{
		Logger::getInstance().print("獲得導入表失敗");
		return;
	}
	PIMAGE_IMPORT_BY_NAME functionName;
	//遍歷導入表
	while (pImportDescriptor->Name != NULL)
	{
		PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
		originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModImageBase + pImportDescriptor->OriginalFirstThunk);
		firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModImageBase + pImportDescriptor->FirstThunk);
		while (originalFirstThunk->u1.AddressOfData != NULL && firstThunk->u1.Function != NULL)
		{
			functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)hModImageBase + originalFirstThunk->u1.AddressOfData);
			//找地址
			if ((DWORD_PTR)MyGetCurrentProcess == firstThunk->u1.Function)
			{
				PDWORD_PTR function = &firstThunk->u1.Function;
				Logger::getInstance().print((std::string)"UnHook! Name:" + functionName->Name + (std::string)"\nAddress:" + Logger::AddressToHexString(function));
				DWORD oldProtect;
				VirtualProtect(&firstThunk->u1.Function, sizeof(firstThunk->u1.Function), PAGE_EXECUTE_READWRITE, &oldProtect);
				firstThunk->u1.Function = (DWORD_PTR)originalFunction;
			}
			++originalFirstThunk;
			++firstThunk;
		}
		++pImportDescriptor;
	}
	originalFunction = nullptr;
}