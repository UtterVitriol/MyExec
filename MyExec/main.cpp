#include <cstdio>
#include "Exec.h"

int main()
{
	DWORD dwPID = GetProcId(L"explorer.exe");

	exec(dwPID, (char*)"dir");
}