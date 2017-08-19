/*
Application:    Code injection into a running process.
Author:            _RT
Dated:            07-March-2014
*/

#include <windows.h>
#include <fstream>
#include <stdlib.h>

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"user32.lib")

typedef BOOL(WINAPI* CreatePrcssParam)(LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES,
	LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCTSTR, LPVOID, LPVOID);

typedef BOOL(WINAPI* CreatePrcssParam2)(LPCTSTR);

struct PARAMETERS {
	LPVOID CreateProcessInj;
	char lpApplicationName[50];
	char lpCommandLine[10];
	LPSECURITY_ATTRIBUTES lpProcessAttributes;
	LPSECURITY_ATTRIBUTES lpThreadAttributes;
	BOOL bInheritHandles;
	DWORD dwCreationFlags;
	LPVOID lpEnvironment;
	LPCTSTR lpCurrentDirectory;
	LPVOID lpStartupInfo;
	LPVOID lpProcessInformation;
};

struct PARAMETERS2 {
	LPVOID CreateProcessInj;
	char lpLibFileName[50];
};

/*
reateProcessA(
	_In_opt_ LPCSTR lpApplicationName,
	_Inout_opt_ LPSTR lpCommandLine,
	_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_ BOOL bInheritHandles,
	_In_ DWORD dwCreationFlags,
	_In_opt_ LPVOID lpEnvironment,
	_In_opt_ LPCSTR lpCurrentDirectory,
	_In_ LPSTARTUPINFOA lpStartupInfo,
	_Out_ LPPROCESS_INFORMATION lpProcessInformation
);*/

int privileges();
DWORD myFunc(PARAMETERS * myparam);
DWORD myFunc2(PARAMETERS2 * myparam);
DWORD Useless();    //used to calculate size of myFunc()


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef LONG KPRIORITY; // Thread priority

typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
	IN       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT   PVOID SystemInformation,
	IN       ULONG SystemInformationLength,
	OUT OPTIONAL  PULONG ReturnLength
	);


DWORD NtProcessFind(LPCWSTR WStr) {
	__int64 bac2, bac3;
	size_t bufferSize = 102400 * 4;
	PSYSTEM_PROCESS_INFORMATION_DETAILD pspid =
		(PSYSTEM_PROCESS_INFORMATION_DETAILD)malloc(bufferSize);
	ULONG ReturnLength;
	PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
	//NTSTATUS status;

	pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)pspid, bufferSize, &ReturnLength);
	for (;; pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {
		printf("ProcessId: %d, ImageFileName: %ls \n", pspid->UniqueProcessId, pspid->ImageName.Buffer);
		//printf("%x", pspid->ImageName.Buffer);
		ReadProcessMemory(GetCurrentProcess(), pspid->ImageName.Buffer, &bac2, 8, NULL);
		ReadProcessMemory(GetCurrentProcess(), WStr, &bac3, 8, NULL);
		if (bac2 == bac3) break;

		if (pspid->NextEntryOffset == 0) return 0;
	}
	return (DWORD)pspid->UniqueProcessId;
}

int main()
{
	DWORD proc = NULL;
	while (1) {
		proc = NtProcessFind(L"notepad.exe");
		if (proc != 0) break;
		Sleep(10);
	}

	privileges();

	_STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	DWORD pid;
	//GetWindowThreadProcessId(FindWindow(NULL, L"Start Menu"), &pid);
	pid = 5728;

	HANDLE p;
	p = OpenProcess(PROCESS_ALL_ACCESS, false, proc);
	if (p == NULL)
	{
		printf("ERROR");
		return 1; //error

	}

	char * AppName = "C:\\Windows\\notepad.exe";
	char * DLL_PATH = "C:\\my64.dll";
	char * CmdLine = "";

	//Writing the structure vital for CreateProcess function

	LPVOID StrtUpInfo = VirtualAllocEx(p, NULL, sizeof(si), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, StrtUpInfo, &si, sizeof(si), NULL);

	LPVOID PrcssInfo = VirtualAllocEx(p, NULL, sizeof(si), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, PrcssInfo, &pi, sizeof(pi), NULL);
	//=========================================================

	//////////// CreateProcessA ///////////////////////////////
	PARAMETERS data = { 0 };
	HMODULE Kernel32 = LoadLibrary(L"Kernel32.dll");
	data.CreateProcessInj = GetProcAddress(Kernel32, "CreateProcessA");
	strcpy_s(data.lpApplicationName, AppName);
	strcpy_s(data.lpCommandLine, CmdLine);
	data.lpProcessAttributes = NULL;
	data.lpThreadAttributes = NULL;
	data.bInheritHandles = FALSE;
	data.dwCreationFlags = NULL;
	data.lpEnvironment = NULL;
	data.lpCurrentDirectory = NULL;
	data.lpStartupInfo = StrtUpInfo;
	data.lpProcessInformation = PrcssInfo;
	//////////// CreateProcessA ///////////////////////////////
	PARAMETERS2 data2 = { 0 };
	data2.CreateProcessInj = GetProcAddress(Kernel32, "LoadLibraryA");
	strcpy_s(data2.lpLibFileName, DLL_PATH);
	//////////// CreateProcessA ///////////////////////////////
//	DWORD size_myFunc = (PBYTE)Useless - (PBYTE)myFunc;  //this gets myFunc's size
	DWORD size_myFunc = (BYTE)&Useless - (BYTE)&myFunc2;
	size_myFunc = 128 + 1;


														 //Writing the code part of myFunc -- Instructions to be executed

	LPVOID MyFuncAddress = VirtualAllocEx(p, NULL, size_myFunc, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	WriteProcessMemory(p, MyFuncAddress, (void*)myFunc, size_myFunc, NULL);
	WriteProcessMemory(p, MyFuncAddress, (void*)myFunc2, size_myFunc, NULL);

	//Writing the data part of myFunc -- Parameters of the functios

	printf("%d", sizeof(PARAMETERS));
	LPVOID DataAddress = VirtualAllocEx(p, NULL, sizeof(PARAMETERS), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//WriteProcessMemory(p, DataAddress, &data, sizeof(PARAMETERS), NULL);
	WriteProcessMemory(p, DataAddress, &data2, sizeof(PARAMETERS), NULL);

	HANDLE thread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)MyFuncAddress, DataAddress, 0, NULL);
	if (thread != 0) {
		//injection completed, not we can wait for it to end and free the memory

		WaitForSingleObject(thread, INFINITE);   //this waits until thread thread has finished

		VirtualFree(MyFuncAddress, 0, MEM_RELEASE); //free myFunc memory

		VirtualFree(DataAddress, 0, MEM_RELEASE); //free data memory

		CloseHandle(thread);
		CloseHandle(p);  //don't wait for the thread to finish, just close the handle to the process

	}
	else {
		printf("Error!");
	}
	return EXIT_SUCCESS;
}

static DWORD myFunc2(PARAMETERS2 * myparam) {

	CreatePrcssParam2 CreatePrcss = (CreatePrcssParam2)myparam->CreateProcessInj;
	BOOL result = CreatePrcss((LPCTSTR)myparam->lpLibFileName);
	return 0;
}

static DWORD myFunc(PARAMETERS * myparam) {

	CreatePrcssParam CreatePrcss = (CreatePrcssParam)myparam->CreateProcessInj;
	BOOL result = CreatePrcss((LPCTSTR)myparam->lpApplicationName, NULL,
		myparam->lpProcessAttributes, myparam->lpThreadAttributes,
		myparam->bInheritHandles, myparam->dwCreationFlags, myparam->lpEnvironment,
		myparam->lpCurrentDirectory, myparam->lpStartupInfo, myparam->lpProcessInformation);
	return 0;
}

int privileges() { // 코드를 집어 넣을수 있도록 특권을 세팅 해줌
	HANDLE Token;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL) == 0) {
			return 1; //FAIL
		}
		else {
			return 0; //SUCCESS
		}
	}
	return 1;
}