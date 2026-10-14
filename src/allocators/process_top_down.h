#pragma once

// Per-process top-down address space allocation, no hook. See process_top_down.cpp.
#include <windows.h>
namespace ProcessTopDown {
void Init();
void OnLowHalf(SIZE_T largestLowBytes);
void LogStats();
}
