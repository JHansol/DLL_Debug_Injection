#include <iostream>
#include "stdio.h"
#include<conio.h>
#include<stdio.h>
#include<windows.h>
#include "string.h"
#include"TlHelp32.h"
#include "atlstr.h"

using namespace std;
int b;
HANDLE hThread;

#define DEF_DLL_PATH    TEXT("c:\\my32.dll")

#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

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

void __declspec(naked) InjectFunction()
{
	__asm
	{
		PUSHAD
		MOV EAX, 0xAAAAAAAA //eventually the address of LoadLibraryA
		PUSH 0xBBBBBBBB //eventually the module name
		call EAX
		POPAD
		//vc is pissy and requires us to emit the hardcoded jump
		__emit 0xE9
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
		__emit 0xCC
	}
}
void __declspec(naked) AfterFunction()
{
}

LPVOID g_pSend = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

LPVOID g_pfWriteFile = NULL;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	g_pfWriteFile = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	// API Hook - WriteFile()
	//   첫 번째 byte 를 0xCC (INT 3) 으로 변경 
	//   (orginal byte 는 백업)
	g_cpdi = pde->u.CreateProcessInfo;		// CREATE_PROCESS_DEBUG_INFO
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,&g_chOrgByte, sizeof(BYTE), NULL);
	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,&g_chINT3, sizeof(BYTE), NULL);

	return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde, DWORD PID)
{
	CONTEXT ctx; // 현재 쓰레드 정보 담아올 구조체
	HANDLE Proces; // OpenProcess할 함수명
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord; // https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx  참조

	if (EXCEPTION_BREAKPOINT == per->ExceptionCode) //  브뽀(INT3) 발생시
	{
		cout << "브뽀 걸린 주소 : " << per->ExceptionAddress << endl;

		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(g_cpdi.hThread, &ctx); //  ctx에 현재 Thread Context 얻어오기

		ULONG FunctionSize = (PBYTE)AfterFunction - (PBYTE)InjectFunction;
		PBYTE LocalFunction = new BYTE[FunctionSize];
		memcpy(LocalFunction, InjectFunction, FunctionSize); // InjectFunction 어셈문을 LocalFunction에 옮긴다.
		Proces = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); // 프로세스 권한 오픈
		PBYTE InjData = (PBYTE)VirtualAllocEx(Proces, NULL, FunctionSize + strlen(DEF_DLL_PATH) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //InjData = InjectFunction함수크기 + DLL path주소크기 만큼을 가상으로 할당시킨다.
		LPVOID injdata2 = InjData; // cout할려면 LPVOID로 해줘야함
		cout << injdata2 << endl;
		DWORD OrgEip = ctx.Eip;

		for (ULONG i = 0; i < FunctionSize - 3; i++)
		{
			if (*(PDWORD)&LocalFunction[i] == 0xAAAAAAAA) // *(PDWORD)(Local+i) == 0xAAAAAAAA
			{
				*(PDWORD)&LocalFunction[i] = (DWORD)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
			}
			if (*(PDWORD)&LocalFunction[i] == 0xBBBBBBBB)
			{
				*(PDWORD)&LocalFunction[i] = (DWORD)InjData + FunctionSize;
			}
			if (*(PDWORD)&LocalFunction[i] == 0xCCCCCCCC)
			{
				//*(PDWORD)&LocalFunction[i] = (DWORD)g_pSend - ((DWORD)&InjData[i] + 4); // WS2_32.SEND 주소 - 가상할당함수[2]+0x04(현주소값) = jmp ws2_32.send 
				*(PDWORD)&LocalFunction[i] = (DWORD)(OrgEip - 1) - ((DWORD)&InjData[i] + 4);
			}
		}
		DWORD dwWritten;
		WriteProcessMemory(Proces, InjData, LocalFunction, FunctionSize, (SIZE_T*)&dwWritten); // 가상 할당 주소에 LocalFunction 값 쓰기
		WriteProcessMemory(Proces, InjData + FunctionSize, (LPVOID)DEF_DLL_PATH, strlen(DEF_DLL_PATH) + 1, (SIZE_T*)&dwWritten); // 가상 할당 주소 끝부분에 DLL path 주소 값 쓰기
		ctx.Eip = (DWORD)InjData; // 현재 스레드 eip 주소를 가상할당한 InjData 주소 넣기

		SetThreadContext(g_cpdi.hThread, &ctx); // eip 수정햇던거 재설정 후 가동

		ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE); // 디버그된 프로세스 진행시킴

		DebugActiveProcessStop(PID); // 디버그 해제

									 //WriteProcessMemory(g_cpdi.hProcess, g_pSend, &g_chINT3, sizeof(BYTE), NULL); // int3로 수정되면 무한 반복

		return TRUE;
	}
	return FALSE;
}

void DebugLoop(DWORD PID)
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus;
	OnExceptionDebugEvent(&de, PID);

	// Debuggee 로부터 event 가 발생할 때까지 기다림
	while (WaitForDebugEvent(&de, INFINITE))
	{
		dwContinueStatus = DBG_CONTINUE;

		// Debuggee 프로세스 생성 혹은 attach 이벤트
		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
//OnCreateProcessDebugEvent(&de);
			LPDEBUG_EVENT pde = &de;
			memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO)); // CREATE_PROCESS_DEBUG_INFO 구조체 정보 받아옴
		}
		// 예외 이벤트
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
		{
			if (OnExceptionDebugEvent(&de, PID))
				continue;
		}
		// Debuggee 프로세스 종료 이벤트
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			// debuggee 종료 -> debugger 종료
			break;
		}

		// Debuggee 의 실행을 재개시킴
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}
int i;
char CmpChar[4] = "mIR";
DWORD Roop()
{
	HANDLE CT32;
	PROCESSENTRY32 ProEnt;
	CT32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(CT32, &ProEnt);
	while (1) {
		i++;
		//printf("%s \n", ProEnt.szExeFile);
		cout << ProEnt.szExeFile[0];
		if (ProEnt.szExeFile[0] == CmpChar[0] && ProEnt.szExeFile[1] == CmpChar[1] && ProEnt.szExeFile[2] == CmpChar[2]) {
			cout << "찾았습니다" << endl;
			break;
		}
		Process32Next(CT32, &ProEnt);
		if (i == 90) { i = 0; ProEnt.th32ProcessID = 0; break; }
	}
	return ProEnt.th32ProcessID;
}



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
		_tprintf(TEXT("ProcessId: %d, ImageFileName: %ls \n"), pspid->UniqueProcessId, pspid->ImageName.Buffer);
		//printf("%x", pspid->ImageName.Buffer);
		ReadProcessMemory(GetCurrentProcess(), pspid->ImageName.Buffer, &bac2, 8, NULL);
		ReadProcessMemory(GetCurrentProcess(), WStr, &bac3, 8, NULL);
		if (bac2 == bac3) break;

		if (pspid->NextEntryOffset == 0) return 0;
	}
	return (DWORD)pspid->UniqueProcessId;
}

int main(void) {
	DWORD proc = NULL;
	/*
	while (1){
	HWND tempHwnd = FindWindowA("mIRC", NULL); // mirc HWND 가져오기
	GetWindowThreadProcessId(tempHwnd, &proc); // mirc HWND 로 PID값 가져오기
	if (proc == NULL) cout << "프로그램을 찾을 수 없습니다." << endl;
	else break;
	Sleep(10);
	}
	*/

	while (1) {
		proc = NtProcessFind(L"procexp.exe");
		if (proc != 0) break;
		Sleep(10);
	}
	// ERROR_NOT_SUPPORTED 오류는 관리되는 실행 파일에만 적용되는 것이 아니라 32 비트 디버거를 사용하여 64 비트 실행 파일을 디버깅하려고 할 때도 발생합니다.
	// x64 플랫폼 대상을 프로젝트에 추가하여 64 비트 버전을 빌드하십시오.

	if (!DebugActiveProcess(proc))    // Attach 시도!
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", proc, GetLastError());
		return 1;
	}


	DebugLoop(proc);

	cin >> b; //자동종료 방지
}