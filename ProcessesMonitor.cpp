#include "headers.h"


BOOL DetectNewProcess (set<DWORD> &seenPIDs)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if( hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    if(Process32First(hProcessSnap, &pe32))
    {
    do
        {
            DWORD pid = pe32.th32ProcessID;

        if(seenPIDs.find(pid) == seenPIDs.end())
        {
            seenPIDs.insert(pid);

            _tprintf(TEXT("\n\n-------------------------------------------------------"));
            _tprintf( TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile );
            _tprintf( TEXT("\n-------------------------------------------------------"));

            dwPriorityClass = 0;
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);

            DWORD size = 512;
            LPTSTR FullPath = new TCHAR[size];
            _tcscpy_s(FullPath, size, TEXT("N/A"));

    if(hProcess == NULL)
    {
            _tcscpy_s(FullPath, size, TEXT("OpenProcess !")); 
    } 
    else 
    {
            dwPriorityClass = GetPriorityClass(hProcess);

    if(!dwPriorityClass)
    {
            _tprintf(TEXT("Priority Class !"));
    }

    if(!QueryFullProcessImageName(hProcess, 0, FullPath, &size))
    {
        if(GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            delete[] FullPath;
            size *= 2;
            FullPath = new TCHAR[size];

        if(!QueryFullProcessImageName(hProcess, 0, FullPath, &size))
        {
            _tcscpy_s(FullPath, size, TEXT("ACCES DENIED !"));
        }
    }
        else
        {
            _tcscpy_s(FullPath, size, TEXT("ACCESS DENIED !"));
        }
    }
        CloseHandle(hProcess); 
    }

        _tprintf( TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID );
        _tprintf( TEXT("\n  Thread count      = %d"),   pe32.cntThreads );
        _tprintf( TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID );
        _tprintf( TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase );
    if(dwPriorityClass)
    {
        _tprintf(TEXT("\n   Priority Class    = %d"), dwPriorityClass);
    } 
    else
    {
        _tprintf(TEXT("\n Priority Class Error !"));
    }
        _tprintf( TEXT("\n  Full Path        =  %s\n"), FullPath);

        ListProcessModules( pe32.th32ProcessID );
        ListProcessThreads( pe32.th32ProcessID );
        delete[] FullPath;
    }
    } 
    while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
    return (TRUE);
}