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
	//   ù ��° byte �� 0xCC (INT 3) ���� ���� 
	//   (orginal byte �� ���)
	g_cpdi = pde->u.CreateProcessInfo;		// CREATE_PROCESS_DEBUG_INFO
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,&g_chOrgByte, sizeof(BYTE), NULL);
	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,&g_chINT3, sizeof(BYTE), NULL);

	return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde, DWORD PID)
{
	CONTEXT ctx; // ���� ������ ���� ��ƿ� ����ü
	HANDLE Proces; // OpenProcess�� �Լ���
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord; // https://msdn.microsoft.com/en-us/library/windows/desktop/aa363082(v=vs.85).aspx  ����

	if (EXCEPTION_BREAKPOINT == per->ExceptionCode) //  ���(INT3) �߻���
	{
		cout << "��� �ɸ� �ּ� : " << per->ExceptionAddress << endl;

		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(g_cpdi.hThread, &ctx); //  ctx�� ���� Thread Context ������

		ULONG FunctionSize = (PBYTE)AfterFunction - (PBYTE)InjectFunction;
		PBYTE LocalFunction = new BYTE[FunctionSize];
		memcpy(LocalFunction, InjectFunction, FunctionSize); // InjectFunction ������� LocalFunction�� �ű��.
		Proces = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); // ���μ��� ���� ����
		PBYTE InjData = (PBYTE)VirtualAllocEx(Proces, NULL, FunctionSize + strlen(DEF_DLL_PATH) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //InjData = InjectFunction�Լ�ũ�� + DLL path�ּ�ũ�� ��ŭ�� �������� �Ҵ��Ų��.
		LPVOID injdata2 = InjData; // cout�ҷ��� LPVOID�� �������
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
				//*(PDWORD)&LocalFunction[i] = (DWORD)g_pSend - ((DWORD)&InjData[i] + 4); // WS2_32.SEND �ּ� - �����Ҵ��Լ�[2]+0x04(���ּҰ�) = jmp ws2_32.send 
				*(PDWORD)&LocalFunction[i] = (DWORD)(OrgEip - 1) - ((DWORD)&InjData[i] + 4);
			}
		}
		DWORD dwWritten;
		WriteProcessMemory(Proces, InjData, LocalFunction, FunctionSize, (SIZE_T*)&dwWritten); // ���� �Ҵ� �ּҿ� LocalFunction �� ����
		WriteProcessMemory(Proces, InjData + FunctionSize, (LPVOID)DEF_DLL_PATH, strlen(DEF_DLL_PATH) + 1, (SIZE_T*)&dwWritten); // ���� �Ҵ� �ּ� ���κп� DLL path �ּ� �� ����
		ctx.Eip = (DWORD)InjData; // ���� ������ eip �ּҸ� �����Ҵ��� InjData �ּ� �ֱ�

		SetThreadContext(g_cpdi.hThread, &ctx); // eip �����޴��� �缳�� �� ����

		ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE); // ����׵� ���μ��� �����Ŵ

		DebugActiveProcessStop(PID); // ����� ����

									 //WriteProcessMemory(g_cpdi.hProcess, g_pSend, &g_chINT3, sizeof(BYTE), NULL); // int3�� �����Ǹ� ���� �ݺ�

		return TRUE;
	}
	return FALSE;
}

void DebugLoop(DWORD PID)
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus;
	OnExceptionDebugEvent(&de, PID);

	// Debuggee �κ��� event �� �߻��� ������ ��ٸ�
	while (WaitForDebugEvent(&de, INFINITE))
	{
		dwContinueStatus = DBG_CONTINUE;

		// Debuggee ���μ��� ���� Ȥ�� attach �̺�Ʈ
		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
//OnCreateProcessDebugEvent(&de);
			LPDEBUG_EVENT pde = &de;
			memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO)); // CREATE_PROCESS_DEBUG_INFO ����ü ���� �޾ƿ�
		}
		// ���� �̺�Ʈ
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
		{
			if (OnExceptionDebugEvent(&de, PID))
				continue;
		}
		// Debuggee ���μ��� ���� �̺�Ʈ
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			// debuggee ���� -> debugger ����
			break;
		}

		// Debuggee �� ������ �簳��Ŵ
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
			cout << "ã�ҽ��ϴ�" << endl;
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
	HWND tempHwnd = FindWindowA("mIRC", NULL); // mirc HWND ��������
	GetWindowThreadProcessId(tempHwnd, &proc); // mirc HWND �� PID�� ��������
	if (proc == NULL) cout << "���α׷��� ã�� �� �����ϴ�." << endl;
	else break;
	Sleep(10);
	}
	*/

	while (1) {
		proc = NtProcessFind(L"procexp.exe");
		if (proc != 0) break;
		Sleep(10);
	}
	// ERROR_NOT_SUPPORTED ������ �����Ǵ� ���� ���Ͽ��� ����Ǵ� ���� �ƴ϶� 32 ��Ʈ ����Ÿ� ����Ͽ� 64 ��Ʈ ���� ������ ������Ϸ��� �� ���� �߻��մϴ�.
	// x64 �÷��� ����� ������Ʈ�� �߰��Ͽ� 64 ��Ʈ ������ �����Ͻʽÿ�.

	if (!DebugActiveProcess(proc))    // Attach �õ�!
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", proc, GetLastError());
		return 1;
	}


	DebugLoop(proc);

	cin >> b; //�ڵ����� ����
}