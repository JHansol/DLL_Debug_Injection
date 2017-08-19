#include <windows.h>
#include <fstream>
#include <stdlib.h>

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"user32.lib")

typedef BOOL(WINAPI* LoadLibraryP)(LPCTSTR);

struct LoadLibrary_para {
	LPVOID CreateProcessInj;
	char lpLibFileName[50];
};

int privileges();
DWORD LibFunc(LoadLibrary_para * myparam);

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef LONG KPRIORITY; 

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
		printf("PID: %d, 실행중인프로세스명: %ls \n", pspid->UniqueProcessId, pspid->ImageName.Buffer);
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
		proc = NtProcessFind(L"procexp64.exe");
		if (proc != 0) break;
		Sleep(10);
	}

	printf("특권 ; %d",privileges() ); //특권주고

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

	char * DLL_PATH = "C:\\sock_dll.dll";

	LPVOID StrtUpInfo = VirtualAllocEx(p, NULL, sizeof(si), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, StrtUpInfo, &si, sizeof(si), NULL);

	LPVOID PrcssInfo = VirtualAllocEx(p, NULL, sizeof(si), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, PrcssInfo, &pi, sizeof(pi), NULL);
	//=========================================================
	LoadLibrary_para data2 = { 0 };
	HMODULE Kernel32 = LoadLibrary(L"Kernel32.dll");
	data2.CreateProcessInj = GetProcAddress(Kernel32, "LoadLibraryA");
	strcpy_s(data2.lpLibFileName, DLL_PATH);
	DWORD size_myFunc = 1280 + 1;
	//////////// LoadLibraryA ///////////////////////////////


	// 작동시킬 명령어 할당해주자
	LPVOID Address = VirtualAllocEx(p, NULL, size_myFunc, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(p, Address, (void*)LibFunc, size_myFunc, NULL);

	// 명령어의 인자 값 할당해주자
	LPVOID DataAddress = VirtualAllocEx(p, NULL, sizeof(LoadLibrary_para), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, DataAddress, &data2, sizeof(LoadLibrary_para), NULL);

	HANDLE thread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)Address, DataAddress, 0, NULL);
	if (thread != 0) { // 주입성공, 메모리를 free 시켜주자
		WaitForSingleObject(thread, INFINITE);   // 쓰레드 완료할때까지 기다림 

		VirtualFree(Address, 0, MEM_RELEASE); //free myFunc memory
		VirtualFree(DataAddress, 0, MEM_RELEASE); //free data memory

		CloseHandle(thread);
		CloseHandle(p);  // OpenProcess 닫아줘야지

	}
	else {
		printf("ERROR");
	}
	return EXIT_SUCCESS;
}

static DWORD LibFunc(LoadLibrary_para * myparam) {

	LoadLibraryP CreatePrcss = (LoadLibraryP)myparam->CreateProcessInj;
	BOOL result = CreatePrcss((LPCTSTR)myparam->lpLibFileName);
	return 0;
}

int privileges() { // 다른 프로세스에 코드를 집어 넣을수 있도록 특권을 세팅 해줌
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