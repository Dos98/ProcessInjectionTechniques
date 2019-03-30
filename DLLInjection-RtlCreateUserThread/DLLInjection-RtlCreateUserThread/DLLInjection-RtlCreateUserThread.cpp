// DLLInjection-RtlCreateUserThread.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// ConsoleApplication2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <stdio.h> 
#include <windows.h>

HANDLE RtlCreateUserThread(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPVOID lpSpace
)
{
	//The prototype of RtlCreateUserThread from undocumented.ntinternals.com
	typedef DWORD(WINAPI * functypeRtlCreateUserThread)(
		HANDLE      ProcessHandle,
		PSECURITY_DESCRIPTOR  SecurityDescriptor,
		BOOL      CreateSuspended,
		ULONG     StackZeroBits,
		PULONG     StackReserved,
		PULONG     StackCommit,
		LPVOID     StartAddress,
		LPVOID     StartParameter,
		HANDLE      ThreadHandle,
		LPVOID     ClientID
		);
	//Get handle for ntdll which contains RtlCreateUserThread
	HANDLE hRemoteThread = NULL;
	HMODULE hNtDllModule = GetModuleHandle("ntdll.dll");
	if (hNtDllModule == NULL)
	{
		return NULL;
	}
	functypeRtlCreateUserThread funcRtlCreateUserThread = (functypeRtlCreateUserThread)GetProcAddress(hNtDllModule, "RtlCreateUserThread");
	if (!funcRtlCreateUserThread)
	{
		return NULL;
	}
	funcRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpBaseAddress, lpSpace,
		&hRemoteThread, NULL);
	DWORD lastError = GetLastError();
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
	hThread = RtlCreateUserThread(hProcess, lpBaseAddress, lpSpace);

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
	puts("Inject into which Process ID: ");
	scanf_s("%u", &pid);
	puts("Method used here is - RtlCreateUserThread");
	int result = injectIntoPID(pid);
	if (result == -1)
	{
		puts("Could not inject into PID");
	}
	system("pause");
}
