// SWIREKIT.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "psapi.h"

// NtCreateThreadEx functionality (necessary for Win7 hooking)
// copied from http://noobys-journey.blogspot.co.il/search/label/NtCreateThreadEx
HANDLE NtCreateThreadEx(HANDLE hProcess, ACCESS_MASK accessMask, LPVOID lpRemoteThreadStart, LPVOID lpParam)
{
	typedef struct
	{
		ULONG Length;
		ULONG Unknown1;
		ULONG Unknown2;
		PULONG Unknown3;
		ULONG Unknown4;
		ULONG Unknown5;
		ULONG Unknown6;
		PULONG Unknown7;
		ULONG Unknown8;

	} UNKNOWN;

	typedef DWORD WINAPI NtCreateThreadEx_PROC(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD Unknown1,
		DWORD Unknown2,
		LPVOID Unknown3
		);

	UNKNOWN Buffer;
	DWORD dw0 = 0;
	DWORD dw1 = 0;
	memset(&Buffer, 0, sizeof(UNKNOWN));

	Buffer.Length = sizeof (UNKNOWN);
	Buffer.Unknown1 = 0x10003;
	Buffer.Unknown2 = 0x8;
	Buffer.Unknown3 = &dw1;
	Buffer.Unknown4 = 0;
	Buffer.Unknown5 = 0x10004;
	Buffer.Unknown6 = 4;
	Buffer.Unknown7 = &dw0;

	NtCreateThreadEx_PROC* VistaCreateThread = (NtCreateThreadEx_PROC*)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

	if (VistaCreateThread == NULL)
		return NULL;

	HANDLE hRemoteThread = NULL;
	HRESULT hRes = 0;

	if (!SUCCEEDED(hRes = VistaCreateThread(
		&hRemoteThread,
		accessMask,
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)lpRemoteThreadStart,
		lpParam,
		FALSE,
		NULL,
		NULL,
		NULL,
		&Buffer
		)))
	{
		int baz = GetLastError();
		return NULL;
	}

	return hRemoteThread;
}

// Get address of function in another process (since addresses aren't shared across processes)
LPVOID GetProcAddressExternal(LPCSTR moduleName, LPCSTR funcName, HANDLE hTargetProcess) {

	// Get local function address
	HMODULE localModule = GetModuleHandleA(moduleName);
	HANDLE localAddress = GetProcAddress(localModule, funcName);

	// Get external modules
	HMODULE modules[100];
	DWORD moduleSize;
	BOOL out = EnumProcessModulesEx(hTargetProcess, modules, (DWORD)100ul, &moduleSize, LIST_MODULES_ALL);

	// Get target module handle (which = the external module offset)
	char curModuleName[100];
	HMODULE remoteModule = NULL;
	for (int i = 0; i < (int)(moduleSize / sizeof(DWORD)); i++) {
		GetModuleBaseNameA(hTargetProcess, modules[i], (LPSTR)&curModuleName, (DWORD)100);
		if (strcmp(moduleName, curModuleName) == 0) {
			remoteModule = modules[i];
			break;
		}
	}
	if (remoteModule == NULL) { return NULL; }

	// Calculate address of function in external process
	unsigned long offset;
	offset = (unsigned long)localAddress - (unsigned long)localModule;
	return (LPVOID)((unsigned long)(remoteModule) + offset);
}

// Injection code modified from http://www.codeproject.com/Articles/4610/Three-Ways-to-Inject-Your-Code-into-Another-Proces
bool injectDLL(DWORD ProcessID) {

	ACCESS_MASK mask = 0x1FFFFFF;
	HANDLE hProcess = OpenProcess(mask, FALSE, ProcessID);

	HANDLE hThread;
	char    szLibPath[_MAX_PATH];
	void*   pLibRemote;
	DWORD   hLibModule;
	
	// initialize szLibPath
	GetFullPathNameA("Win32Project1.dll", sizeof(szLibPath), szLibPath, NULL);
	HMODULE LLB = LoadLibraryA(szLibPath);

	// 1. Allocate memory in the remote process for szLibPath
	// 2. Write szLibPath to the allocated memory
	pLibRemote = ::VirtualAllocEx(hProcess, NULL, sizeof(szLibPath),
		MEM_COMMIT, PAGE_READWRITE);
	::WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath,
		sizeof(szLibPath), NULL);
	
	// Load "LibSpy.dll" into the remote process
	// (via CreateRemoteThread & LoadLibrary)
	LoadLibraryA(szLibPath);
	LPVOID LLAddr = GetProcAddressExternal("kernel32.dll", "LoadLibraryA", hProcess);
	hThread = NtCreateThreadEx(hProcess, mask, (LPTHREAD_START_ROUTINE)LLAddr, pLibRemote);
	WaitForSingleObject(hThread, INFINITE);

	// Get handle of the loaded module
	BOOL exitCode = GetExitCodeThread(hThread, &hLibModule);

	// Clean up
	::CloseHandle(hThread);
	::VirtualFreeEx(hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE);
	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	// Inject a DLL into process specified by its PID
	injectDLL((DWORD)5080l);
	return 0;
}