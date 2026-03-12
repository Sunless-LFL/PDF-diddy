#include "RuleEngine.h"
#include <iostream>
#include <algorithm>

RuleEngine::RuleEngine()
{
    // nothing for now
}

bool RuleEngine::EqualsI(const std::wstring& a, const std::wstring& b)
{
    if (a.size() != b.size()) return false;

    for (size_t i = 0; i < a.size(); ++i)
    {
        if (towlower(a[i]) != towlower(b[i])) return false;
    }
    return true;
}

bool RuleEngine::InListI(const std::wstring& value, const std::vector<std::wstring>& list)
{
    for (const auto& x : list)
    {
        if (EqualsI(value, x)) return true;
    }
    return false;
}

void RuleEngine::Evaluate(const ProcessEvent& event)
{
    // =========================
    // RULE 1 (PDF Security):
    // If a PDF reader spawns a command/scripting tool => ALERT
    // =========================

    // IMPORTANT:
    // This rule needs your ProcessEvent to include parent process name.
    // So ProcessEvent should have: std::wstring parentName;
    // If you don't have it yet, add it and fill it in your monitor.

    const std::vector<std::wstring> pdfReaders = {
        L"AcroRd32.exe",     // Adobe Reader
        L"Acrobat.exe",      // Adobe Acrobat
        L"SumatraPDF.exe",
        L"FoxitPDFReader.exe",
        L"FoxitReader.exe",
        L"msedge.exe",       // sometimes used to open PDFs
        L"chrome.exe"        // sometimes used to open PDFs
    };

    const std::vector<std::wstring> suspiciousChildren = {
        L"cmd.exe",
        L"powershell.exe",
        L"pwsh.exe",
        L"wscript.exe",
        L"cscript.exe",
        L"mshta.exe",
        L"rundll32.exe",
        L"regsvr32.exe"
    };

    // If you haven't added parentName yet, comment this rule out for now.
    const bool parentIsPdfReader = InListI(event.parentName, pdfReaders);
    const bool childIsSuspicious = InListI(event.name, suspiciousChildren);

    if (parentIsPdfReader && childIsSuspicious)
    {
        std::wcout << L"[ALERT][HIGH] PDF reader spawned suspicious child process\n"
                   << L"  Parent: " << event.parentName << L"\n"
                   << L"  Child : " << event.name << L"\n"
                   << L"  Path  : " << event.path << L"\n"
                   << std::endl;
    }
}