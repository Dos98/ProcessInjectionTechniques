// PoC_Dll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

//extern "C" __declspec(dllexport) int poc(int code, WPARAM wParam, LPARAM lParam) {
extern "C" __declspec(dllexport) BOOL poc() {
	MessageBox(NULL, "POC called!", "Inject All The Things!", 0);

	//return(CallNextHookEx(NULL, code, wParam, lParam));
	return TRUE;
}
