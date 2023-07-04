#include "Exec.h"

int exec()
{
	char binaryName[255];
	const char* envName = "COMSPEC";
	const char* command = "cmd.exe pwd";
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

	// explorer.exe 10172
	// notepade.exe 30120

	hParentProc = OpenProcess(MAXIMUM_ALLOWED, false, 30120);
	if (INVALID_HANDLE_VALUE == hParentProc)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}
	
	if (!CreatePipe(&hStdOutR, &hStdOutW, NULL, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
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
		return 1;
	}
	
	/*ZeroMemory(&sAttr, sizeof(sAttr));
	sAttr.nLength = sizeof(sAttr);
	sAttr.bInheritHandle = TRUE;
	sAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&hStdInR, &hStdInW, NULL, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}*/
	/*if (!SetHandleInformation(hStdInW, HANDLE_FLAG_INHERIT, 0))
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}*/


	iResult = GetEnvironmentVariableA(envName, binaryName, 255);
	if (iResult <= 0)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}


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
		return 1;
	}

	iResult = InitializeProcThreadAttributeList(sInfo.lpAttributeList, 1, 0, &attrSize);
	if (0 == iResult)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}

	iResult = UpdateProcThreadAttribute(sInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProc, sizeof(hParentProc), NULL, NULL);
	if (0 == iResult)
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}


	sInfo.StartupInfo.hStdOutput = hMyDuped;
	sInfo.StartupInfo.hStdError = hMyDuped;
	//sInfo.StartupInfo.hStdInput = hStdOutR;
	sInfo.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
	sInfo.StartupInfo.cb = sizeof(sInfo);
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/// End PID Spoofing. ////////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	std::string mycmdl = binaryName;
	mycmdl.append(" /c dir");

	if (CreateProcessA(NULL, (LPSTR)mycmdl.c_str(), NULL, NULL, TRUE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sInfo.StartupInfo, &pInfo))
	{
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

	}
	else
	{
		dwError = GetLastError();
		DERR(std::system_category().message(dwError).c_str(), dwError);
		return 1;
	}

	return 0;
}