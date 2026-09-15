#pragma once
#include <Windows.h>
#include <cstring>

struct MemModule {
    void* base;
    MemModule() : base(nullptr) {}
    MemModule(void* b) : base(b) {}
};

static DWORD ProtectFromSectionChars(DWORD chars) {
    BOOL exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL read = (chars & IMAGE_SCN_MEM_READ) != 0;
    BOOL write = (chars & IMAGE_SCN_MEM_WRITE) != 0;
    if (exec && read && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)          return PAGE_EXECUTE_READ;
    if (exec && write)         return PAGE_EXECUTE_WRITECOPY;
    if (exec)                  return PAGE_EXECUTE;
    if (read && write)         return PAGE_READWRITE;
    if (read)                  return PAGE_READONLY;
    if (write)                 return PAGE_WRITECOPY;
    return PAGE_NOACCESS;
}

void* GetExport(const MemModule& mod, const char* name) {
    if (!mod.base) return nullptr;
    auto base = (uint8_t*)mod.base;

    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return nullptr;

    auto ed = (PIMAGE_EXPORT_DIRECTORY)(base + dir.VirtualAddress);
    auto names = (DWORD*)(base + ed->AddressOfNames);
    auto ords = (WORD*)(base + ed->AddressOfNameOrdinals);
    auto funs = (DWORD*)(base + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        const char* nm = (const char*)(base + names[i]);
        if (_stricmp(nm, name) == 0) {
            WORD ord = ords[i];
            DWORD rva = funs[ord];
            return (void*)(base + rva);
        }
    }
    return nullptr;
}

MemModule MapImage(const uint8_t* dll, size_t dllSize) {
    MemModule out;

    if (!dll || dllSize < sizeof(IMAGE_DOS_HEADER)) return out;

    // Copy raw into temp buffer
    void* raw = VirtualAlloc(nullptr, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!raw) return out;
    std::memcpy(raw, dll, dllSize);

    auto dos = (PIMAGE_DOS_HEADER)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { VirtualFree(raw, 0, MEM_RELEASE); return out; }

    auto nt = (PIMAGE_NT_HEADERS)((uint8_t*)raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { VirtualFree(raw, 0, MEM_RELEASE); return out; }

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    uint8_t* base = (uint8_t*)VirtualAlloc((LPVOID)nt->OptionalHeader.ImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) base = (uint8_t*)VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) { VirtualFree(raw, 0, MEM_RELEASE); return out; }

    // Copy headers
    std::memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->SizeOfRawData == 0) continue;
        std::memcpy(base + sec->VirtualAddress,
            (uint8_t*)raw + sec->PointerToRawData,
            sec->SizeOfRawData);
    }

    // Relocations
    DWORD_PTR delta = (DWORD_PTR)base - nt->OptionalHeader.ImageBase;
    if (delta && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto reloc = (PIMAGE_BASE_RELOCATION)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto end = (uint8_t*)reloc + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        while ((uint8_t*)reloc < end && reloc->SizeOfBlock) {
            size_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto list = (WORD*)(reloc + 1);
            for (size_t i = 0; i < count; ++i) {
                WORD typeOff = list[i];
                WORD type = typeOff >> 12;
                WORD off = typeOff & 0x0FFF;
#ifdef _WIN64
                if (type == IMAGE_REL_BASED_DIR64) {
                    auto* p = (ULONG_PTR*)(base + reloc->VirtualAddress + off);
                    *p += delta;
                }
#else
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    auto* p = (ULONG_PTR*)(base + reloc->VirtualAddress + off);
                    *p += delta;
                }
#endif
            }
            reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }

    // Imports
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; ++imp) {
            const char* lib = (const char*)(base + imp->Name);
            HMODULE m = LoadLibraryA(lib);
            if (!m) continue;

            auto thunk = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
            auto origThunk = (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk);
            for (; thunk->u1.AddressOfData; ++thunk, ++origThunk) {
                FARPROC addr = nullptr;
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    addr = GetProcAddress(m, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto ibn = (PIMAGE_IMPORT_BY_NAME)(base + origThunk->u1.AddressOfData);
                    addr = GetProcAddress(m, (LPCSTR)ibn->Name);
                }
#ifdef _WIN64
                thunk->u1.Function = (ULONGLONG)addr;
#else
                thunk->u1.Function = (DWORD)addr;
#endif
            }
        }
    }

    // Final section protections
    sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD prot = ProtectFromSectionChars(sec->Characteristics);
        DWORD old;
        SIZE_T size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (size)
            VirtualProtect(base + sec->VirtualAddress, size, prot, &old);
    }

    // Make headers RX or at least R
    {
        DWORD old;
        VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    }

    VirtualFree(raw, 0, MEM_RELEASE);
    MemModule result(base);
    return result;
}
