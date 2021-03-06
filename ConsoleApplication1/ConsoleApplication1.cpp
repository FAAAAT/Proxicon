// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#define _CRT_SECURE_NO_WARNINGS

#include "pch.h"
#include <iostream>
#include "LSPInstaller.h"
#include <TChar.h>
#include <ATLCONV.h>
using std::string;
using std::cin;
using std::cout;
using std::endl;
using std::wcin;

void showError();
LPCWSTR ToCW(const char* strIn);
int main(int argc, char* argv[])
{
	OutputDebugString(ToCW("Installer show up"));
	setlocale(LC_ALL, "Chinese-simplified");
	char content[2048];
	cin.getline(content, 2048);
	while (strcmp(content, "exit")) {
		if (strcmp(content, "install") == 0) {
			cout << "Please input path:";
			wchar_t wcontent[2048];
			wcin.getline(wcontent, 2048);

			if (!InstallProvider(wcontent)) {
				cout << "install failed!" << endl;
				showError();
			}
		}

		if (strcmp(content, "uninstall")==0) {
			if (!RemoveProvider()) {
				cout << "install failed!" << endl;
			}
		}
		cin.getline(content, 2048);

	}
}

void showError() {
	LPTSTR lpMsgBuf;
	int error = WSAGetLastError();
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		// Default language     
		(LPTSTR)&lpMsgBuf,
		0,
		NULL);
	// Process any inserts in lpMsgBuf.    
	// ...     
	// Display the string.     
	_tprintf(L"%ws",lpMsgBuf);
	// Free the buffer.     
	LocalFree(lpMsgBuf);
}

LPCWSTR ToCW(const char * strIn) {
	
	USES_CONVERSION;
	LPCWSTR wszClassName = new WCHAR[strlen(strIn)+1];
	wcscpy((LPTSTR)wszClassName, T2W((LPTSTR)strIn));
	return wszClassName;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
