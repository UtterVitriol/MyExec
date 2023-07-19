#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <system_error>

#ifndef NDEBUG
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define DERR(s, d) fprintf(stderr, "[-]: %s:%d:%s(): %s - %d\n", __FILENAME__, __LINE__, __func__, s, d)
#define DMSG(s) printf("[+]: %s:%d:%s(): %s\n", __FILENAME__, __LINE__, __func__, s)
#else
#define DERR(s,d)
#define DMSG(s)
#endif

class Exec
{
};

int exec(char* command);
DWORD GetProcId(const wchar_t* procName);