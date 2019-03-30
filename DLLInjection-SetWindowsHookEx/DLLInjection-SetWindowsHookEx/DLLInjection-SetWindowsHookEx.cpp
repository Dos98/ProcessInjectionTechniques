// DLLInjection-SetWindowsHookEx.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "pch.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>



int main(int argc, char* argv)
{
	int pid; wchar_t *pname;
	puts("Inject into which PID: ");
	scanf_s("%u", &pid);
	puts("Inject into which process: ");
	scanf_s("%s", &pname);
	// wprintf(pname);
	puts("Method used to attach thread is : SetWindowsHookEx");
	int result = injectIntoPID(pid);
	if (result == -1)
	{
		puts("Could not inject into PID");
	}
	system("pause");
}
