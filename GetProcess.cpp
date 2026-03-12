#include "headers.h"

DWORD dwPriorityClass = 0;
HANDLE hProcessSnap = NULL;
PROCESSENTRY32 pe32 = {};

void print_error(TCHAR const* msg){
     _tprintf(_T("Error: %s\n"), msg);
}


BOOL ListProcessModules(DWORD dwPID)
{
    _tprintf(TEXT("ListProcessModules not implemented for PID %lu\n"), dwPID);
    return TRUE; 
}

BOOL ListProcessThreads(DWORD dwPID)
{
    _tprintf(TEXT("ListProcessThreads not implemented for PID %lu\n"), dwPID);
    return TRUE; 
}


BOOL GetProcessList()
{
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(hProcessSnap == INVALID_HANDLE_VALUE) 
    {
        print_error(TEXT("Createtoolhelp32Snapshot (of process)"));
        return (FALSE);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if( !Process32First(hProcessSnap , &pe32)){

        print_error(TEXT("Process32First")); // showing the error
        CloseHandle(hProcessSnap);
        return(FALSE);
    }

    do 
    {
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
    while(Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return(TRUE);
}