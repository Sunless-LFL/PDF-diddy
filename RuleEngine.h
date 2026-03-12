#pragma once

#include <string>
#include <vector>
#include "headers.h"   // must contain ProcessEvent

class RuleEngine
{
public:
    RuleEngine();
    void Evaluate(const ProcessEvent& event);

private:
    static bool EqualsI(const std::wstring& a, const std::wstring& b);
    static bool InListI(const std::wstring& value, const std::vector<std::wstring>& list);
};