// DLLInjection-CreateRemoteThread.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

bool inject(int processid)
{
	HANDLE hProcess, AllocAdresse, hRemoteThread;
	int pid = processid;
	char dll_path[] = "C:\\DLLTest.dll";
	SIZE_T dll_len = sizeof(dll_path);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (hProcess == NULL)
	{
		cout << "[*] Could not create a handle to the process PID: " << pid << "\n";
		return FALSE;
	}

	AllocAdresse = VirtualAllocEx(hProcess, 0, dll_len, MEM_COMMIT, PAGE_READWRITE);

	SIZE_T *written = 0;
	WriteProcessMemory(hProcess, (void*)AllocAdresse, (void*)dll_path, dll_len, written);


	LPDWORD thread_id = 0;
	hRemoteThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"), AllocAdresse, 0, thread_id);

	if (hRemoteThread == NULL)
	{
		cout << "Could not create a remote thread!\n";
		return FALSE;
	}

	cout << "RemoteThread was created.\n";
	WaitForSingleObject(hRemoteThread, INFINITE);
	cout << "Finished!\n";
	VirtualFreeEx(hProcess, AllocAdresse, dll_len, MEM_RESERVE);
	CloseHandle(hProcess);
	return TRUE;
}

// steps:
// OpenProcess
// hRemoteThread = virtualAllocEx
// WriteProcessMemory()
// hRemoteThread =	CreateRemoteThread()
// WaitForSingleObject

// Injection off dll by remote thread
// check for injection of exe as remote thread
// injection techniques of dll 
// check for traps
// in


int main(void)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bool injected = FALSE;

	if (Process32First(hSnapshot, &ProcessEntry))
	{
		do
		{
			cout << ProcessEntry.th32ProcessID << "\t" << ProcessEntry.szExeFile << "\n";
			if (injected == FALSE)
			{
				// injected = inject(ProcessEntry.th32ProcessID);
				injected = inject(4264);
			}
		} while (Process32Next(hSnapshot, &ProcessEntry));
	}
	CloseHandle(hSnapshot);
	getchar();
}
