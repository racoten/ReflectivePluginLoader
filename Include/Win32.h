#pragma once
#include <Windows.h>

// ---------------------------------------------------------------------------
// WinApiTable — abstraction layer for Win API calls.
// Defaults to raw Win32 APIs. Swap in SealApi/KunaiGate pointers to get
// evasion-wrapped calls without changing any loader code.
// ---------------------------------------------------------------------------
struct WinApiTable {
    decltype(&::VirtualAlloc)    VirtualAlloc;
    decltype(&::VirtualFree)     VirtualFree;
    decltype(&::VirtualProtect)  VirtualProtect;
    decltype(&::VirtualQuery)    VirtualQuery;
    decltype(&::LoadLibraryA)    LoadLibraryA;
    decltype(&::GetProcAddress)  GetProcAddress;
    decltype(&::FreeLibrary)     FreeLibrary;
    decltype(&::GetModuleFileNameA) GetModuleFileNameA;
    decltype(&::HeapAlloc)       HeapAlloc;
    decltype(&::HeapFree)        HeapFree;
    decltype(&::GetProcessHeap)  GetProcessHeap;
};

static WinApiTable DefaultWinApiTable() {
    return {
        ::VirtualAlloc,
        ::VirtualFree,
        ::VirtualProtect,
        ::VirtualQuery,
        ::LoadLibraryA,
        ::GetProcAddress,
        ::FreeLibrary,
        ::GetModuleFileNameA,
        ::HeapAlloc,
        ::HeapFree,
        ::GetProcessHeap,
    };
}
