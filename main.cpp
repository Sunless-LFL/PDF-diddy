#include "headers.h"

int _tmain()
{
    set<DWORD> seenPIDs;

    // Phase 1
    GetProcessList(); // logs all existing processes

    // Phase 2
    while(true)
    {
        Sleep(2000);                  
        DetectNewProcess(seenPIDs);   
    }

    return 0;
}




