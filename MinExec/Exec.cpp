#include "Exec.h"

int exec(char* command)
{
	char binaryName[255];
	const char* envName = "COMSPEC";
	std::string sCommand = "";
	int iResult = 0;
	DWORD dwError = 0;

	SECURITY_ATTRIBUTES saAttr = { 0 };
	STARTUPINFOA sInfo = { 0 };
	PROCESS_INFORMATION pInfo = { 0 };
	HANDLE hParentProc = INVALID_HANDLE_VALUE;
	int ree = 0;

	HANDLE hStdOutR = NULL;
	HANDLE hStdOutW = NULL;

	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;


	if (!CreatePipe(&hStdOutR, &hStdOutW, &saAttr, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	sInfo.dwFlags = STARTF_USESTDHANDLES;
	sInfo.hStdOutput = hStdOutW;
	sInfo.hStdError = hStdOutW;


	/*if (!SetHandleInformation(hStdOutR, HANDLE_FLAG_INHERIT, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}*/

	/*ZeroMemory(&sAttr, sizeof(sAttr));
	sAttr.nLength = sizeof(sAttr);
	sAttr.bInheritHandle = TRUE;
	sAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&hStdInR, &hStdInW, NULL, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}*/
	/*if (!SetHandleInformation(hStdInW, HANDLE_FLAG_INHERIT, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}*/


	iResult = GetEnvironmentVariableA(envName, binaryName, 255);
	if (iResult <= 0)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	sCommand.append(binaryName);
	sCommand.append(" /c ");
	sCommand.append(command);





	if (!CreateProcessA(NULL, (LPSTR)sCommand.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	char buff[4096] = { 0 };
	std::string sResponse{};
	//sResponse.resize(

	DWORD dwRead = 0;
	DWORD dwToRead = 0;
	BOOL bSuccess = FALSE;


	std::string test{0};


	test.resize(4096);
	BOOL bEnded = FALSE;
	// loop here
	for (; !bEnded;)
	{
		bEnded = WaitForSingleObject(pInfo.hProcess, 50) == WAIT_OBJECT_0;

		for (;;)
		{
			test.clear();
			if (!PeekNamedPipe(hStdOutR, NULL, 0, NULL, &dwToRead, 0))
			{
				break;
			}

			if (!dwToRead)
			{
				break;
			}

			if (!ReadFile(hStdOutR, (LPVOID)test.data(), sizeof(buff) - 1, &dwRead, NULL))
			{
				break;
			}

			printf("test: %s\n", test.c_str());
		}
	}

	DWORD dwExit = 69;

	GetExitCodeProcess(pInfo.hProcess, &dwExit);

	printf("Exit: %d\n", dwExit);

	//PeekNamedPipe(hStdOutR, 0, 0, 0, &dwToRead, 0);

	//while (dwToRead)
	//{
	//	printf("Bytes: %d\n", dwToRead);
	//	bSuccess = ReadFile(hStdOutR, buff, sizeof(buff) - 1, &dwRead, NULL);
	//	//printf("F: %s\n", buff);
	//	PeekNamedPipe(hStdOutR, 0, 0, 0, &dwToRead, 0);
	//}


	//WaitForSingleObject(pInfo.hProcess, INFINITE);



	CloseHandle(pInfo.hProcess);
	CloseHandle(pInfo.hThread);

	CloseHandle(hStdOutR);
	CloseHandle(hStdOutW);

	return 0;
}


DWORD GetProcId(const wchar_t* procName) {

	DWORD procId = 0;

	/* CreateToolhelp32Snapshot - Takes snapshot of specified processes.
	*  TH32CS_SNAPPROCESS - Include all processes in the system snapshot
	*/
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// INVALID_HANDLE_VALUE - Error code for CreateToolhelp32Snapshot.
	if (hSnap != INVALID_HANDLE_VALUE) {

		// PROCESSENTRY32 - Describes entry in system process snapshot list (hSnap).
		PROCESSENTRY32 procEntry{};

		// Must set dwSize before calling Process32First.
		procEntry.dwSize = sizeof(procEntry);

		// Process32First - Retrieves information about frist process in system snapshot (hSnap).
		if (Process32First(hSnap, &procEntry)) {
			do {

				/* _wcsicmp - Lexicographical wide string case-insensitive compare.
				*  szExeFile - Name of executable file for the process.
				*/
				if (!_wcsicmp(procEntry.szExeFile, procName)) {

					// the32ProcessID - Process ID of process entry.
					procId = procEntry.th32ProcessID;
					break;
				}

				// Process32Next - Retrieves information about next process in system snapshot (hSnap).
			} while (Process32Next(hSnap, &procEntry));
		}
	}

	CloseHandle(hSnap);
	return procId;
}