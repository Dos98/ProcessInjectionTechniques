// DLLInjection-NtCreateThreadEx.cpp : This file contains the 'main' function. Program execution
// begins and ends there.


#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>

HANDLE NtCreateThreadEx(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPVOID lpSpace
)
{
	//The prototype of NtCreateThreadEx from undocumented.ntinternals.com
	typedef DWORD(WINAPI * functypeNtCreateThreadEx)(
		PHANDLE                 ThreadHandle,
		ACCESS_MASK             DesiredAccess,
		LPVOID                  ObjectAttributes,
		HANDLE                  ProcessHandle,
		LPTHREAD_START_ROUTINE  lpStartAddress,
		LPVOID                  lpParameter,
		BOOL                    CreateSuspended,
		DWORD                   dwStackSize,
		DWORD                   Unknown1,
		DWORD                   Unknown2,
		LPVOID                  Unknown3
		);
	HANDLE                      hRemoteThread = NULL;
	HMODULE                     hNtDllModule = NULL;
	functypeNtCreateThreadEx    funcNtCreateThreadEx = NULL;
	//Get handle for ntdll which contains NtCreateThreadEx
	hNtDllModule = GetModuleHandle("ntdll.dll");
	if (hNtDllModule == NULL)
	{
		return NULL;
	}
	funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(hNtDllModule, "NtCreateThreadEx");
	if (!funcNtCreateThreadEx)
	{
		return NULL;
	}
	funcNtCreateThreadEx(&hRemoteThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, lpSpace, FALSE, NULL, NULL, NULL, NULL);
	return hRemoteThread;
}

int injectIntoPID(int process)
{
	DWORD pid = (DWORD)process;
	const char* dll = "C:\\v.dll";
	//Gets the process handle for the target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (OpenProcess == NULL)
	{
		puts("Could not find process");
	}
	//Retrieves kernel32.dll module handle for getting loadlibrary base address
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	//Gets address for LoadLibraryA in kernel32.dll
	LPVOID lpBaseAddress = (LPVOID)GetProcAddress(hModule, "LoadLibraryA");
	if (lpBaseAddress == NULL)
	{
		puts("Unable to locate LoadLibraryA");
		return -1;
	}
	//Allocates space inside for inject.dll to our target process
	LPVOID lpSpace = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpSpace == NULL)
	{
		printf("Could not allocate memory in process %u", (int)process);
		return -1;
	}
	//Write inject.dll to memory of process
	int n = WriteProcessMemory(hProcess, lpSpace, dll, strlen(dll), NULL);
	if (n == 0)
	{
		puts("Could not write to process's address space");
		return -1;
	}
	HANDLE hThread;

	hThread = NtCreateThreadEx(hProcess, lpBaseAddress, lpSpace);
	if (hThread == NULL)
	{
		return -1;
	}
	else
	{
		DWORD threadId = GetThreadId(hThread);
		DWORD processId = GetProcessIdOfThread(hThread);
		printf("Injected thread id: %u for pid: %u", threadId, processId);
		getchar();
		getchar();
		getchar();
		CloseHandle(hProcess);
		return 0;
	}
}

int main(int argc, char* argv)
{
	int pid;
	puts("Inject into which PID: ");
	scanf_s("%u", &pid);
	puts("Method used to attach thread is : NtCreateThread");
	int result = injectIntoPID(pid);
	if (result == -1)
	{
		puts("Could not inject into PID");
	}
	system("pause");
}
