#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <set>

using namespace std;

// Global variables
extern DWORD dwPriorityClass;
extern HANDLE hProcessSnap;
extern PROCESSENTRY32 pe32;

// Function prototypes
BOOL GetProcessList();
BOOL DetectNewProcess(set<DWORD>& seenPIDs);
BOOL ListProcessModules(DWORD dwPID);
BOOL ListProcessThreads(DWORD dwOwnerPID);
void print_error(TCHAR const* msg);
