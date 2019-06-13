#include "basic.h"

#include <iostream>

using namespace std;

int main(int argc, char** argv) {

	DWORD	dwPid;

	cout << "Enter a process id to inject shellcode into: ";
	cin >> dwPid;

	injectShellcode(dwPid);

	return 0;
}