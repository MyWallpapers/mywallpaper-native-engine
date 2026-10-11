#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include "mw_native_sdk.h"
#include "module_lifetime.h"
#ifdef MW_BACKEND_FRIDA_GUM
#include "gum_backend.h"
#else
#include "hook_backend_policy.h"
#include <MinHook.h>
#endif
#include "resident_hooks.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <set>
#include <sstream>
#include <iomanip>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using Json = nlohmann::json;
constexpr std::size_t kMaxAddonIdBytes = 128;

enum class AddonStateKind {
    Active,
    AwaitingModule,
    Stopped,
    Draining,
    Failed,
};

const char* StateName(AddonStateKind state) {
    switch (state) {
    case AddonStateKind::Active: return "active";
    case AddonStateKind::AwaitingModule: return "awaitingModule";
    case AddonStateKind::Stopped: return "stopped";
    case AddonStateKind::Draining: return "draining";
    case AddonStateKind::Failed: return "failed";
    }
    return "failed";
}

struct AddonState;

struct HookRecord {
    AddonState* owner = nullptr;
    void* target = nullptr;
};

struct AddonState {
    std::string id;
    std::wstring canonical_path;
    std::array<uint8_t, 32> image_sha256{}; // Identity of the permanently resident DLL image.
    std::atomic_uint32_t owner_pid{0};
    std::atomic_uint64_t owner_creation_time{0};
    std::atomic_bool owner_alive{true};
    std::recursive_mutex lifecycle_mutex;
    HMODULE module = nullptr; // Kept loaded for the rest of the process.
    MwAddonApi api{};
    MwHostApi host{};
    void* instance_context = nullptr;
    bool instance_created = false;
    AddonStateKind state = AddonStateKind::Failed;
    MwStatus last_code = MW_OK;
    std::string last_error;
    Json settings = Json::object();
    std::atomic_bool accepting_hooks{false};
    std::set<uint64_t> hook_ids; // Protected by Runtime::backend_mutex.
    std::string backend_diagnostic; // Protected by Runtime::backend_mutex.
    mutable std::mutex symbols_mutex;
    std::map<std::pair<std::wstring, std::string>, Json> pending_symbols;
    std::map<std::pair<std::wstring, std::string>, void*> resolved_symbols;
};

struct Runtime {
    std::recursive_mutex registry_mutex; // Registry only; never held across callbacks.
    std::mutex loader_mutex; // Serialize new images without blocking existing instances.
    std::mutex backend_mutex;
    std::mutex sessions_mutex;
    std::map<std::string, std::unique_ptr<AddonState>, std::less<>> addons;
    std::map<uint64_t, HookRecord> hooks;
    std::set<std::pair<uint32_t, uint64_t>> active_sessions;
    uint64_t next_hook_id = 1;
    std::atomic_uint32_t active_workers{0};
    std::atomic_uint32_t active_owner_monitors{0};
    std::atomic_uint64_t worker_sessions_started{0};
    bool hook_backend_ready = false;
};

struct WorkerSession {
    uint32_t owner_pid = 0;
    uint64_t owner_creation_time = 0;
    std::atomic_bool owner_lost{false};
    std::atomic_bool shutdown_requested{false};
};

Runtime& GetRuntime() {
    // Process-lifetime allocation is intentional: add-ons and in-flight detours
    // may retain host/context and original-pointer storage after cooperative stop.
    static Runtime* runtime = new Runtime();
    return *runtime;
}

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    if (value.size() > static_cast<std::size_t>(INT_MAX)) {
        return {};
    }
    const int input_length = static_cast<int>(value.size());
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), input_length, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            input_length, result.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return result;
}

bool Utf8ToWide(std::string_view value, std::wstring* result) {
    if (result == nullptr || value.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    if (value.empty()) {
        result->clear();
        return true;
    }
    const int input_length = static_cast<int>(value.size());
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), input_length, nullptr, 0);
    if (required <= 0) {
        return false;
    }
    result->assign(static_cast<std::size_t>(required), L'\0');
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        input_length, result->data(), required) == required;
}

std::wstring LowerPath(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.size() >= 2 && path[1] == L':') {
        path[0] = static_cast<wchar_t>(std::towlower(path[0]));
    }
    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return path;
}

bool Sha256File(const std::wstring& path, std::array<uint8_t, 32>* digest,
    std::string* error) {
    if (digest == nullptr) {
        if (error != nullptr) *error = "SHA-256 output is missing";
        return false;
    }
    auto fail_status = [error](const char* operation, NTSTATUS status) {
        if (error != nullptr) {
            *error = std::string(operation) + " failed with NTSTATUS " +
                std::to_string(static_cast<uint32_t>(status));
        }
    };

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
        BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        fail_status("BCryptOpenAlgorithmProvider(SHA-256)", status);
        return false;
    }
    struct AlgorithmGuard {
        BCRYPT_ALG_HANDLE value;
        ~AlgorithmGuard() { if (value != nullptr) BCryptCloseAlgorithmProvider(value, 0); }
    } algorithm_guard{algorithm};

    ULONG object_length = 0;
    ULONG property_length = 0;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length),
        &property_length, 0);
    if (status < 0 || property_length != sizeof(object_length)) {
        fail_status("BCryptGetProperty(OBJECT_LENGTH)", status);
        return false;
    }
    std::vector<uint8_t> hash_object(object_length);
    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(algorithm, &hash, hash_object.data(), object_length,
        nullptr, 0, 0);
    if (status < 0) {
        fail_status("BCryptCreateHash(SHA-256)", status);
        return false;
    }
    struct HashGuard {
        BCRYPT_HASH_HANDLE value;
        ~HashGuard() { if (value != nullptr) BCryptDestroyHash(value); }
    } hash_guard{hash};

    std::ifstream input(std::filesystem::path(path), std::ios::binary);
    if (!input) {
        if (error != nullptr) *error = "could not open add-on DLL to verify its SHA-256";
        return false;
    }
    std::array<uint8_t, 64 * 1024> buffer{};
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
            status = BCryptHashData(hash, buffer.data(), static_cast<ULONG>(count), 0);
            if (status < 0) {
                fail_status("BCryptHashData(SHA-256)", status);
                return false;
            }
        }
    }
    if (!input.eof()) {
        if (error != nullptr) *error = "could not read add-on DLL while verifying its SHA-256";
        return false;
    }
    status = BCryptFinishHash(hash, digest->data(), static_cast<ULONG>(digest->size()), 0);
    if (status < 0) {
        fail_status("BCryptFinishHash(SHA-256)", status);
        return false;
    }
    return true;
}

bool IsImageBackedAddress(const void* address) {
    if (address == nullptr) {
        return false;
    }
    MEMORY_BASIC_INFORMATION memory{};
    return VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory) &&
        memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE &&
        memory.AllocationBase != nullptr;
}

bool CanonicalAddonPath(std::string_view utf8, std::wstring* path) {
    if (path == nullptr || utf8.empty()) {
        return false;
    }
    std::wstring requested;
    if (!Utf8ToWide(utf8, &requested)) {
        return false;
    }
    const std::filesystem::path input(requested);
    if (!input.is_absolute()) {
        return false;
    }
    DWORD needed = GetFullPathNameW(requested.c_str(), 0, nullptr, nullptr);
    if (needed == 0 || needed > 32768) {
        return false;
    }
    std::wstring full(static_cast<std::size_t>(needed), L'\0');
    const DWORD written = GetFullPathNameW(requested.c_str(), needed, full.data(), nullptr);
    if (written == 0 || written >= needed) {
        return false;
    }
    full.resize(written);
    *path = std::move(full);
    return true;
}

MwStatus MapHookStatus(MH_STATUS status) {
    switch (status) {
    case MH_OK:
    case MH_ERROR_ALREADY_INITIALIZED:
        return MW_OK;
    case MH_ERROR_MODULE_NOT_FOUND:
        return MW_ERROR_MODULE_NOT_READY;
    case MH_ERROR_FUNCTION_NOT_FOUND:
        return MW_ERROR_SYMBOL_NOT_FOUND;
    case MH_ERROR_NOT_CREATED:
    case MH_ERROR_ENABLED:
    case MH_ERROR_DISABLED:
    case MH_ERROR_ALREADY_CREATED:
    case MH_ERROR_REENTRANT_CALL:
        return MW_ERROR_STATE;
    default:
        return MW_ERROR_HOOK;
    }
}

const char* HookStatusName(MH_STATUS status) {
    switch (status) {
    case MH_OK: return "MH_OK";
    case MH_ERROR_ALREADY_INITIALIZED: return "MH_ERROR_ALREADY_INITIALIZED";
    case MH_ERROR_NOT_INITIALIZED: return "MH_ERROR_NOT_INITIALIZED";
    case MH_ERROR_UNABLE_TO_UNINITIALIZE: return "MH_ERROR_UNABLE_TO_UNINITIALIZE";
    case MH_ERROR_ALREADY_CREATED: return "MH_ERROR_ALREADY_CREATED";
    case MH_ERROR_NOT_CREATED: return "MH_ERROR_NOT_CREATED";
    case MH_ERROR_ENABLED: return "MH_ERROR_ENABLED";
    case MH_ERROR_DISABLED: return "MH_ERROR_DISABLED";
    case MH_ERROR_NOT_EXECUTABLE: return "MH_ERROR_NOT_EXECUTABLE";
    case MH_ERROR_DETOURS_TRANSACTION_BEGIN: return "MH_ERROR_DETOURS_TRANSACTION_BEGIN";
    case MH_ERROR_DETOURS_TRANSACTION_COMMIT: return "MH_ERROR_DETOURS_TRANSACTION_COMMIT";
    case MH_ERROR_UNSUPPORTED_FUNCTION: return "MH_ERROR_UNSUPPORTED_FUNCTION";
    case MH_ERROR_MEMORY_ALLOC: return "MH_ERROR_MEMORY_ALLOC";
    case MH_ERROR_MODULE_NOT_FOUND: return "MH_ERROR_MODULE_NOT_FOUND";
    case MH_ERROR_FUNCTION_NOT_FOUND: return "MH_ERROR_FUNCTION_NOT_FOUND";
    case MH_ERROR_PARTIAL_FAILURE: return "MH_ERROR_PARTIAL_FAILURE";
    case MH_ERROR_REENTRANT_CALL: return "MH_ERROR_REENTRANT_CALL";
    }
    return "MH_STATUS_UNKNOWN";
}

std::string HookStatusMessage(const char* operation, MH_STATUS status) {
    const char* text = MH_StatusToString(status);
    std::string message = operation == nullptr ? "MinHook" : operation;
    message += ": ";
    message += HookStatusName(status);
    if (text != nullptr) {
        message += " (";
        message += text;
        message += ')';
    }
    return message;
}

void RecordBackendDiagnosticLocked(AddonState& addon, const char* operation,
    MH_STATUS status) {
    addon.backend_diagnostic = HookStatusMessage(operation, status);
}

AddonState* GetAddonContext(void* context) {
    return static_cast<AddonState*>(context);
}

MwStatus MW_CALL HostLog(void* context, const char* message_utf8) {
    if (GetAddonContext(context) == nullptr || message_utf8 == nullptr) {
        return MW_ERROR_ARGUMENT;
    }
    OutputDebugStringA("[mw-native-addon] ");
    OutputDebugStringA(message_utf8);
    OutputDebugStringA("\n");
    return MW_OK;
}

MwStatus MW_CALL HostResolveExport(void* context, const wchar_t* module_name,
    const char* export_name, void** target) {
    if (GetAddonContext(context) == nullptr || module_name == nullptr ||
        *module_name == L'\0' || export_name == nullptr || *export_name == '\0' ||
        target == nullptr) {
        return MW_ERROR_ARGUMENT;
    }
    *target = nullptr;
    // A plain GetModuleHandle has an unload window before GetProcAddress.
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(0, module_name, &module)) {
        return MW_ERROR_MODULE_NOT_READY;
    }
    FARPROC proc = GetProcAddress(module, export_name);
    if (proc == nullptr) {
        FreeLibrary(module);
        return MW_ERROR_SYMBOL_NOT_FOUND;
    }
    // Forwarded exports can belong to a different image: pin the actual code.
    const auto pin = mw::module_lifetime::PinAddress(reinterpret_cast<void*>(proc));
    FreeLibrary(module);
    if (pin.disposition == mw::module_lifetime::PinDisposition::Failure) {
        return MW_ERROR_HOOK;
    }
    *target = reinterpret_cast<void*>(proc);
    return MW_OK;
}

bool SymbolModuleIdentity(HMODULE module, Json* identity) {
    if (!module || !identity) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(*dos) ||
        dos->e_lfanew > 65536) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const uint32_t size = nt->OptionalHeader.SizeOfImage;
    const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (directory.VirtualAddress >= size || directory.Size > size - directory.VirtualAddress)
        return false;
    const auto* debug = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(base + directory.VirtualAddress);
    for (size_t i = 0; i < directory.Size / sizeof(*debug); ++i) {
        if (debug[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW || debug[i].SizeOfData < 25 ||
            debug[i].AddressOfRawData >= size ||
            debug[i].SizeOfData > size - debug[i].AddressOfRawData) continue;
        const uint8_t* cv = base + debug[i].AddressOfRawData;
        if (std::memcmp(cv, "RSDS", 4) != 0) continue;
        uint32_t age = 0;
        std::memcpy(&age, cv + 20, sizeof(age));
        const char* pdb_path = reinterpret_cast<const char*>(cv + 24);
        const size_t pdb_length = strnlen_s(pdb_path, debug[i].SizeOfData - 24);
        if (pdb_length == 0 || pdb_length == debug[i].SizeOfData - 24) return false;
        const std::string pdb_file = std::filesystem::path(std::string(pdb_path, pdb_length)).filename().string();
        std::ostringstream guid;
        for (int byte = 4; byte < 20; ++byte)
            guid << std::hex << std::setfill('0') << std::setw(2) << unsigned(cv[byte]);
        std::wstring path(32768, L'\0');
        const DWORD count = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
        if (!count || count >= path.size()) return false;
        path.resize(count);
        *identity = Json{
            {"path", WideToUtf8(path)}, {"base", reinterpret_cast<uintptr_t>(module)},
            {"size", size}, {"machine", nt->FileHeader.Machine},
            {"timestamp", nt->FileHeader.TimeDateStamp}, {"checksum", nt->OptionalHeader.CheckSum},
            {"pdbGuid", guid.str()}, {"pdbAge", age}, {"pdbFile", pdb_file}
        };
        return true;
    }
    return false;
}

bool ExecutableRva(HMODULE module, uint64_t rva) {
    const auto* base = reinterpret_cast<const uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (rva >= nt->OptionalHeader.SizeOfImage) return false;
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            rva >= section[i].VirtualAddress &&
            rva - section[i].VirtualAddress < section[i].Misc.VirtualSize) return true;
    }
    return false;
}

MwStatus MW_CALL HostResolveSymbol(void* context, const wchar_t* module_name,
    const char* symbol_name, void** target) {
    AddonState* addon = GetAddonContext(context);
    if (!addon || !module_name || !*module_name || !symbol_name || !*symbol_name || !target)
        return MW_ERROR_ARGUMENT;
    *target = nullptr;
    const auto key = std::make_pair(LowerPath(module_name), std::string(symbol_name));
    std::lock_guard symbols_lock(addon->symbols_mutex);
    const auto resolved = addon->resolved_symbols.find(key);
    if (resolved != addon->resolved_symbols.end()) {
        *target = resolved->second;
        return *target ? MW_OK : MW_ERROR_SYMBOL_NOT_FOUND;
    }
    if (addon->pending_symbols.contains(key)) return MW_ERROR_SYMBOL_PENDING;
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(0, module_name, &module)) return MW_ERROR_MODULE_NOT_READY;
    if (mw::module_lifetime::PinAddress(module).disposition ==
        mw::module_lifetime::PinDisposition::Failure) {
        FreeLibrary(module);
        return MW_ERROR_ADDON;
    }
    Json request;
    const bool identified = SymbolModuleIdentity(module, &request);
    FreeLibrary(module);
    if (!identified) return MW_ERROR_SYMBOL_NOT_FOUND;
    request["module"] = WideToUtf8(module_name);
    request["name"] = symbol_name;
    addon->pending_symbols.emplace(key, std::move(request));
    return MW_ERROR_SYMBOL_PENDING;
}

MwStatus MW_CALL HostHookCreate(void* context, void* target, void* detour,
    void** original, uint64_t* hook_id_out) {
    AddonState* addon = GetAddonContext(context);
    if (addon == nullptr || target == nullptr || detour == nullptr ||
        original == nullptr || hook_id_out == nullptr ||
        reinterpret_cast<uintptr_t>(original) % alignof(void*) != 0) {
        return MW_ERROR_ARGUMENT;
    }
    if (!addon->accepting_hooks.load(std::memory_order_acquire) ||
        !addon->owner_alive.load(std::memory_order_acquire)) {
        return MW_ERROR_STATE;
    }
    const auto target_pin = mw::module_lifetime::PinAddress(target);
    const auto detour_pin = mw::module_lifetime::PinAddress(detour);
    if (target_pin.disposition == mw::module_lifetime::PinDisposition::Failure ||
        detour_pin.disposition == mw::module_lifetime::PinDisposition::Failure) {
        return MW_ERROR_HOOK;
    }
    Runtime& runtime = GetRuntime();
    if (mw::hooks::IsOperationInProgress()) {
        return MW_ERROR_STATE;
    }
    std::lock_guard lock(runtime.backend_mutex);
    if (!addon->accepting_hooks.load(std::memory_order_acquire) ||
        !addon->owner_alive.load(std::memory_order_acquire) ||
        !runtime.hook_backend_ready) {
        return MW_ERROR_STATE;
    }
    if (runtime.next_hook_id == 0) {
        return MW_ERROR_STATE;
    }
    const uint64_t id = runtime.next_hook_id++;
    try {
        runtime.hooks.emplace(id, HookRecord{addon, target});
        addon->hook_ids.insert(id);
    } catch (...) {
        runtime.hooks.erase(id);
        addon->hook_ids.erase(id);
        return MW_ERROR_HOOK;
    }

    const MH_STATUS backend_status = mw::hooks::Create(
        reinterpret_cast<ULONG_PTR>(addon), target, detour, original);
    const MwStatus status = MapHookStatus(backend_status);
    if (status != MW_OK) {
        RecordBackendDiagnosticLocked(*addon, "MH_CreateHookEx", backend_status);
        addon->hook_ids.erase(id);
        runtime.hooks.erase(id);
        return status;
    }
    *hook_id_out = id;
    return MW_OK;
}

MwStatus OperateHook(void* context, uint64_t hook_id, int operation) {
    AddonState* addon = GetAddonContext(context);
    if (addon == nullptr || hook_id == 0) {
        return MW_ERROR_ARGUMENT;
    }
    Runtime& runtime = GetRuntime();
    if (mw::hooks::IsOperationInProgress()) {
        return MW_ERROR_STATE;
    }
    std::lock_guard lock(runtime.backend_mutex);
    const auto found = runtime.hooks.find(hook_id);
    if (found == runtime.hooks.end() || found->second.owner != addon) {
        return MW_ERROR_STATE;
    }
    const ULONG_PTR ident = reinterpret_cast<ULONG_PTR>(addon);
    MH_STATUS backend_status = MH_ERROR_NOT_CREATED;
    const char* operation_name = nullptr;
    switch (operation) {
    case 0:
        if (!addon->accepting_hooks.load(std::memory_order_acquire) ||
            !addon->owner_alive.load(std::memory_order_acquire)) return MW_ERROR_STATE;
        operation_name = "MH_EnableHookEx";
        backend_status = mw::hooks::Enable(ident, found->second.target);
        if (backend_status == MH_ERROR_ENABLED) {
            return MW_OK;
        }
        break;
    case 1:
        operation_name = "MH_DisableHookEx";
        backend_status = mw::hooks::Disable(ident, found->second.target);
        if (backend_status == MH_ERROR_DISABLED) {
            return MW_OK;
        }
        break;
    case 2:
        operation_name = "MH_RemoveHookEx";
        backend_status = mw::hooks::Remove(ident, found->second.target);
        if (backend_status == MH_OK) {
            addon->hook_ids.erase(hook_id);
            runtime.hooks.erase(found);
            return MW_OK;
        }
        break;
    default:
        return MW_ERROR_ARGUMENT;
    }
    if (backend_status != MH_OK) {
        RecordBackendDiagnosticLocked(*addon, operation_name, backend_status);
    }
    return MapHookStatus(backend_status);
}

MwStatus MW_CALL HostHookEnable(void* context, uint64_t hook_id) {
    return OperateHook(context, hook_id, 0);
}

MwStatus MW_CALL HostHookDisable(void* context, uint64_t hook_id) {
    return OperateHook(context, hook_id, 1);
}

MwStatus MW_CALL HostHookRemove(void* context, uint64_t hook_id) {
    return OperateHook(context, hook_id, 2);
}

Json AddonStatusJson(Runtime& runtime, const AddonState& addon) {
    std::size_t hook_count = 0;
    std::string backend_diagnostic;
    {
        std::lock_guard lock(runtime.backend_mutex);
        hook_count = addon.hook_ids.size();
        backend_diagnostic = addon.backend_diagnostic;
    }
    Json result = {
        {"addonId", addon.id},
        {"state", StateName(addon.state)},
        {"hookCount", hook_count},
        {"lastCode", addon.last_code},
        {"ownerPid", addon.owner_pid.load()},
        {"ownerCreationTime", addon.owner_creation_time.load()},
    };
    if (!addon.last_error.empty()) {
        result["error"] = addon.last_error;
    }
    if (!backend_diagnostic.empty()) {
        result["backendDiagnostic"] = std::move(backend_diagnostic);
    }
    {
        std::lock_guard symbols_lock(addon.symbols_mutex);
        result["pendingSymbols"] = Json::array();
        for (const auto& [key, request] : addon.pending_symbols) {
            (void)key;
            result["pendingSymbols"].push_back(request);
        }
        result["resolvedSymbolCount"] = addon.resolved_symbols.size();
    }
    return result;
}

Json AllAddonStatuses(Runtime& runtime) {
    std::lock_guard registry_lock(runtime.registry_mutex);
    Json result = Json::array();
    for (const auto& [id, addon] : runtime.addons) {
        std::unique_lock instance_lock(addon->lifecycle_mutex, std::try_to_lock);
        if (instance_lock.owns_lock()) {
            result.push_back(AddonStatusJson(runtime, *addon));
        } else {
            result.push_back(Json{{"addonId", id}, {"state", "busy"},
                {"ownerPid", addon->owner_pid.load()},
                {"ownerCreationTime", addon->owner_creation_time.load()}});
        }
    }
    return result;
}

void SetFailure(AddonState& addon, MwStatus code, std::string error) {
    addon.last_code = code;
    addon.last_error = std::move(error);
}

std::string CallbackError(const char* phase, MwStatus code) {
    return std::string("add-on ") + phase + " callback returned " + std::to_string(code);
}

void BuildHostApi(AddonState& addon) {
    addon.host = {};
    addon.host.struct_size = sizeof(MwHostApi);
    addon.host.abi_version = MW_NATIVE_ABI_VERSION;
    addon.host.addon_context = &addon;
    addon.host.log = &HostLog;
    addon.host.resolve_export = &HostResolveExport;
    addon.host.hook_create = &HostHookCreate;
    addon.host.hook_enable = &HostHookEnable;
    addon.host.hook_disable = &HostHookDisable;
    addon.host.hook_remove = &HostHookRemove;
    addon.host.resolve_symbol = &HostResolveSymbol;
}

MwStatus CleanupHooks(AddonState& addon, std::string* error) {
    Runtime& runtime = GetRuntime();
    std::lock_guard lock(runtime.backend_mutex);
    MwStatus first_error = MW_OK;
    std::vector<uint64_t> ids(addon.hook_ids.begin(), addon.hook_ids.end());
    for (uint64_t id : ids) {
        const auto found = runtime.hooks.find(id);
        if (found == runtime.hooks.end()) {
            addon.hook_ids.erase(id);
            continue;
        }
        const MH_STATUS status = mw::hooks::Remove(
            reinterpret_cast<ULONG_PTR>(&addon), found->second.target);
        if (status == MH_OK) {
            addon.hook_ids.erase(id);
            runtime.hooks.erase(found);
        } else if (first_error == MW_OK) {
            first_error = MapHookStatus(status);
            if (error != nullptr) {
                *error = HookStatusMessage("MH_RemoveHookEx", status);
            }
            RecordBackendDiagnosticLocked(addon, "MH_RemoveHookEx", status);
        }
    }
    return first_error;
}

MwStatus CallStop(AddonState& addon, bool require_active, std::string* error);

MwStatus CallStart(AddonState& addon, std::string* error) {
    if (!addon.owner_alive.load(std::memory_order_acquire)) return MW_ERROR_STATE;
    if (!addon.instance_created) {
        MwStatus created = MW_ERROR_ADDON;
        try {
            created = addon.api.create_instance(&addon.host, addon.id.c_str(),
                &addon.instance_context);
        } catch (...) { created = MW_ERROR_ADDON; }
        if (created != MW_OK) {
            addon.state = AddonStateKind::Failed;
            if (error != nullptr) *error = CallbackError("create_instance", created);
            return created;
        }
        addon.instance_created = true;
    }
    addon.accepting_hooks.store(true, std::memory_order_release);
    const std::string settings_json = addon.settings.dump();
    MwStatus status = MW_ERROR_ADDON;
    try {
        status = addon.api.start(addon.instance_context, settings_json.c_str());
    } catch (...) {
        status = MW_ERROR_ADDON;
        if (error != nullptr) {
            *error = "add-on start callback raised a native exception";
        }
    }
    if (status == MW_OK) {
        // Start may own resources without any engine hook. Mark it active
        // before owner-loss cleanup so Stop cannot mistake it for a no-op.
        addon.state = AddonStateKind::Active;
        if (!addon.owner_alive.load(std::memory_order_acquire)) {
            (void)CallStop(addon, false, error);
            if (error) *error = "owner exited while start callback was running";
            return MW_ERROR_STATE;
        }
        addon.last_code = MW_OK;
        addon.last_error.clear();
        return MW_OK;
    }

    addon.accepting_hooks.store(false, std::memory_order_release);
    if (error != nullptr && error->empty()) {
        *error = CallbackError("start", status);
    }
    MwStatus rollback_status = MW_OK;
    try {
        // A failed start can have partially initialized add-on state. Ask it to
        // unwind cooperatively; DLL code remains resident if the callback fails.
        rollback_status = addon.api.stop(addon.instance_context);
    } catch (...) {
        rollback_status = MW_ERROR_ADDON;
        if (error != nullptr && error->empty()) {
            *error = "add-on stop callback raised a native exception during rollback";
        }
    }
    std::string cleanup_error;
    const MwStatus cleanup_status = CleanupHooks(addon, &cleanup_error);
    if (cleanup_status != MW_OK) {
        addon.state = AddonStateKind::Draining;
        addon.last_code = cleanup_status;
        addon.last_error = cleanup_error;
        if (error != nullptr) {
            *error = cleanup_error;
        }
        return cleanup_status;
    }
    if (rollback_status == MW_ERROR_DRAIN_PENDING) {
        addon.state = AddonStateKind::Draining;
        addon.last_code = rollback_status;
        addon.last_error = "failed start rolled back hooks; entered calls are still draining";
        if (error != nullptr) {
            *error = addon.last_error;
        }
        return rollback_status;
    }
    if (rollback_status != MW_OK) {
        addon.state = AddonStateKind::Draining;
        addon.last_code = rollback_status;
        addon.last_error = CallbackError("stop during start rollback", rollback_status);
        if (error != nullptr) {
            *error = addon.last_error;
        }
        return rollback_status;
    }
    addon.last_code = status;
    addon.last_error = error == nullptr ? CallbackError("start", status) : *error;
    addon.state = (status == MW_ERROR_MODULE_NOT_READY || status == MW_ERROR_SYMBOL_PENDING)
        ? AddonStateKind::AwaitingModule
        : AddonStateKind::Failed;
    return status;
}

MwStatus CallStop(AddonState& addon, bool require_active, std::string* error) {
    if (require_active && addon.state != AddonStateKind::Active &&
        addon.state != AddonStateKind::Draining) {
        if (error != nullptr) {
            *error = "add-on is not active or draining";
        }
        return MW_ERROR_STATE;
    }
    if (!require_active && addon.state == AddonStateKind::Stopped) {
        std::lock_guard lock(GetRuntime().backend_mutex);
        if (addon.hook_ids.empty()) {
            return MW_OK;
        }
    }

    addon.accepting_hooks.store(false, std::memory_order_release);
    MwStatus callback_status = MW_ERROR_ADDON;
    try {
        callback_status = addon.instance_created ? addon.api.stop(addon.instance_context) : MW_OK;
    } catch (...) {
        if (error != nullptr) {
            *error = "add-on stop callback raised a native exception";
        }
    }
    std::string cleanup_error;
    const MwStatus cleanup_status = CleanupHooks(addon, &cleanup_error);
    if (cleanup_status != MW_OK) {
        addon.state = AddonStateKind::Draining;
        addon.last_code = cleanup_status;
        addon.last_error = cleanup_error;
        if (error != nullptr) {
            *error = cleanup_error;
        }
        return cleanup_status;
    }
    if (callback_status == MW_ERROR_DRAIN_PENDING) {
        addon.state = AddonStateKind::Draining;
        addon.last_code = callback_status;
        addon.last_error = "entered add-on calls are still draining; retry stop";
        if (error != nullptr) {
            *error = addon.last_error;
        }
        return callback_status;
    }
    if (callback_status != MW_OK) {
        addon.state = AddonStateKind::Draining;
        addon.last_code = callback_status;
        addon.last_error = error != nullptr && !error->empty()
            ? *error : CallbackError("stop", callback_status);
        if (error != nullptr && error->empty()) {
            *error = addon.last_error;
        }
        return callback_status;
    }

    addon.state = AddonStateKind::Stopped;
    addon.last_code = MW_OK;
    addon.last_error.clear();
    return MW_OK;
}

bool IsSafeAddonId(std::string_view id) {
    if (id.empty() || id.size() > kMaxAddonIdBytes) {
        return false;
    }
    return std::all_of(id.begin(), id.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.';
    });
}

bool IsSessionActive(Runtime& runtime, uint32_t owner_pid,
    uint64_t owner_creation_time) {
    if (owner_pid == 0 || owner_creation_time == 0) {
        return false;
    }
    std::lock_guard lock(runtime.sessions_mutex);
    return runtime.active_sessions.contains({owner_pid, owner_creation_time});
}

Json MakeResponse(Runtime& runtime, const WorkerSession& session,
    const Json& id, MwStatus code,
    std::string error = {}) {
    Json response = {
        {"id", id},
        {"ok", code == MW_OK},
        {"code", code},
        {"addons", AllAddonStatuses(runtime)},
    };
    {
        std::lock_guard lock(runtime.backend_mutex);
#ifdef MW_BACKEND_FRIDA_GUM
        MwGumBackendMetrics metrics{};
        metrics.struct_size = sizeof(metrics);
        MwGumBackendGetMetrics(&metrics);
        response["backend"] = {
            {"name", "frida-gum"},
            {"gumReplaceMode", "fast-resident"},
            {"retentionPolicy", "resident-target-dispatch"},
            {"physicalTargetRestoreOnStop", false},
            {"bridgeRemainsPatched", metrics.bridge_remains_patched != 0},
            {"retiredGenerations", metrics.retired_generations},
            {"logicalDisableCount", metrics.logical_disable_count},
            {"instrumentedTargets", metrics.instrumented_targets},
            {"activeHooks", metrics.active_hooks},
            {"retainedHookRecords", metrics.retained_hook_records},
            {"residentGatewayCount", metrics.retained_gateways},
            {"residentGatewayBytes", metrics.gateway_region_bytes},
            {"gatewayRegionCount", metrics.gateway_region_count},
            {"gatewaySlotBytes", metrics.gateway_slot_bytes},
            {"gumReplaceCount", metrics.gum_replace_count},
        };
#else
        const uint64_t regions = MwBackendTrampolineRegionCount();
        const auto resident = mw::hooks::GetMetrics();
        response["backend"] = {
            {"name", "minhook-detours"},
            {"retentionPolicy", "resident-owner-target-detour"},
            {"physicalTargetRestoreOnStop", false},
            {"physicalRemovalPolicy", "resident-bypass"},
            {"bridgeRemainsPatched", true},
            {"retainedHookRecords", resident.retained_records},
            {"installedBridges", resident.installed_bridges},
            {"registeredHooks", resident.registered_hooks},
            {"activeHooks", resident.active_hooks},
            {"logicalDisableCount", resident.logical_disables},
            {"hookReuseCount", resident.reuse_count},
            {"retiredGenerations", MwBackendRetiredTrampolineCount()},
            {"retiredTrampolines", MwBackendRetiredTrampolineCount()},
            {"trampolineRegionCount", regions},
            {"trampolineRegionBytes", regions * 65536u},
            {"trampolineSlotBytes", MwBackendTrampolineSlotBytes()},
        };
#endif
    }
    response["agentLifecycle"] = {
        {"activeWorkers", runtime.active_workers.load(std::memory_order_acquire)},
        {"activeOwnerMonitors", runtime.active_owner_monitors.load(std::memory_order_acquire)},
        {"workerSessionsStarted", runtime.worker_sessions_started.load(std::memory_order_relaxed)},
        {"ownerPid", session.owner_pid},
        {"ownerCreationTime", session.owner_creation_time},
    };
    const auto module_metrics = mw::module_lifetime::GetMetrics();
    response["modules"] = {
        {"retentionPolicy", "process-lifetime-image-pins"},
        {"trackedModules", module_metrics.tracked_modules},
        {"requests", module_metrics.requests},
        {"alreadyPinned", module_metrics.already_pinned},
        {"nonImageAddresses", module_metrics.non_image_addresses},
        {"failures", module_metrics.failures},
    };
    if (!error.empty()) {
        response["error"] = std::move(error);
    }
    return response;
}

bool ReadSettings(const Json& request, Json* settings) {
    if (settings == nullptr) {
        return false;
    }
    const auto found = request.find("settings");
    if (found == request.end()) {
        *settings = Json::object();
        return true;
    }
    if (!found->is_object()) {
        return false;
    }
    *settings = *found;
    return true;
}

Json HandleRequest(Runtime& runtime, WorkerSession& session, const Json& request) {
    Json id = request.is_object() && request.contains("id") ? request["id"] : Json(nullptr);
    std::unique_lock registry_lock(runtime.registry_mutex);
    if (!request.is_object() || !id.is_number_unsigned() ||
        !request.contains("operation") || !request["operation"].is_string()) {
        return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT,
            "request must have a uint64 id and operation string");
    }
    const std::string operation = request["operation"].get<std::string>();
    if (operation == "status") {
        return MakeResponse(runtime, session, id, MW_OK);
    }

    if (operation == "shutdown") {
        MwStatus first_status = MW_OK;
        std::string first_error;
        std::vector<AddonState*> owned;
        for (auto& [key, addon] : runtime.addons) {
            (void)key;
            if (addon->owner_pid != session.owner_pid ||
                addon->owner_creation_time != session.owner_creation_time) {
                continue;
            }
            owned.push_back(addon.get());
        }
        registry_lock.unlock();
        for (AddonState* addon : owned) {
            std::unique_lock instance_lock(addon->lifecycle_mutex, std::try_to_lock);
            std::string error;
            const MwStatus status = instance_lock.owns_lock()
                ? CallStop(*addon, false, &error) : MW_ERROR_BUSY;
            if (status == MW_ERROR_BUSY) error = "add-on callback is still running";
            if (status != MW_OK && first_status == MW_OK) {
                first_status = status;
                first_error = std::move(error);
            }
        }
        // A cooperative drain must be retryable through the same pipe.
        session.shutdown_requested.store(first_status == MW_OK, std::memory_order_release);
        return MakeResponse(runtime, session, id, first_status, std::move(first_error));
    }

    const auto addon_id_value = request.find("addonId");
    if (addon_id_value == request.end() || !addon_id_value->is_string()) {
        return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "addonId is required");
    }
    const std::string addon_id = addon_id_value->get<std::string>();
    if (!IsSafeAddonId(addon_id)) {
        return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "addonId has invalid characters or length");
    }

    const auto found = runtime.addons.find(addon_id);

    if (operation == "load") {
        const auto path_value = request.find("path");
        if (path_value == request.end() || !path_value->is_string()) {
            return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "load requires an absolute path");
        }
        std::wstring canonical_path;
        if (!CanonicalAddonPath(path_value->get_ref<const std::string&>(), &canonical_path)) {
            return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "add-on path must be an absolute valid UTF-8 path");
        }
        Json settings;
        if (!ReadSettings(request, &settings)) {
            return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "settings must be a JSON object");
        }
        if (found != runtime.addons.end()) {
            AddonState& addon = *found->second;
            std::unique_lock instance_lock(addon.lifecycle_mutex, std::try_to_lock);
            if (!instance_lock.owns_lock()) {
                return MakeResponse(runtime, session, id, MW_ERROR_BUSY, "add-on callback is still running");
            }
            registry_lock.unlock();
            if ((addon.owner_pid != session.owner_pid ||
                addon.owner_creation_time != session.owner_creation_time) &&
                IsSessionActive(runtime, addon.owner_pid, addon.owner_creation_time)) {
                return MakeResponse(runtime, session, id, MW_ERROR_STATE,
                    "this logical add-on identity is already owned by another active companion");
            }
            std::array<uint8_t, 32> requested_image_sha256{};
            std::string hash_error;
            if (!Sha256File(canonical_path, &requested_image_sha256, &hash_error)) {
                return MakeResponse(runtime, session, id, MW_ERROR_ADDON,
                    "could not verify re-materialized add-on DLL: " + hash_error);
            }
            if (requested_image_sha256 != addon.image_sha256) {
                return MakeResponse(runtime, session, id, MW_ERROR_STATE,
                    "artifact identity resolves to different add-on DLL bytes");
            }
            if (addon.state == AddonStateKind::Draining) {
                std::string error;
                const MwStatus drain_status = CallStop(addon, false, &error);
                if (drain_status != MW_OK) {
                    return MakeResponse(runtime, session, id, drain_status, std::move(error));
                }
            } else if (addon.state != AddonStateKind::Stopped &&
                addon.state != AddonStateKind::AwaitingModule) {
                return MakeResponse(runtime, session, id, MW_ERROR_STATE,
                    "add-on must be stopped before a new companion session loads it");
            }
            addon.owner_pid = session.owner_pid;
            addon.owner_creation_time = session.owner_creation_time;
            addon.owner_alive.store(!session.owner_lost.load(std::memory_order_acquire), std::memory_order_release);
            addon.settings = std::move(settings);
            std::string error;
            const MwStatus status = CallStart(addon, &error);
            if (status != MW_OK) {
                SetFailure(addon, status, error);
            }
            return MakeResponse(runtime, session, id, status, std::move(error));
        }
        std::unique_lock loader_lock(runtime.loader_mutex, std::try_to_lock);
        if (!loader_lock.owns_lock()) {
            return MakeResponse(runtime, session, id, MW_ERROR_BUSY, "another add-on image is being initialized");
        }
        registry_lock.unlock();
        std::array<uint8_t, 32> image_sha256{};
        std::string hash_error;
        if (!Sha256File(canonical_path, &image_sha256, &hash_error)) {
            return MakeResponse(runtime, session, id, MW_ERROR_ADDON,
                "could not verify add-on DLL: " + hash_error);
        }
        HMODULE resident_image = nullptr;
        registry_lock.lock();
        for (const auto& [other_id, other] : runtime.addons) {
            (void)other_id;
            if (other->image_sha256 == image_sha256) { resident_image = other->module; break; }
        }
        registry_lock.unlock();
        HMODULE module = nullptr;
        if (resident_image) {
            (void)GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                reinterpret_cast<const wchar_t*>(resident_image), &module);
        } else {
            module = LoadLibraryExW(canonical_path.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        }
        if (module == nullptr) {
            return MakeResponse(runtime, session, id, MW_ERROR_ADDON,
                "LoadLibraryExW failed with Win32 error " + std::to_string(GetLastError()));
        }
        std::array<uint8_t, 32> post_load_image_sha256{};
        if (!Sha256File(canonical_path, &post_load_image_sha256, &hash_error) ||
            post_load_image_sha256 != image_sha256) {
            FreeLibrary(module);
            return MakeResponse(runtime, session, id, MW_ERROR_ADDON,
                hash_error.empty() ? "add-on DLL changed while it was being loaded" :
                    "could not recheck add-on DLL after loading: " + hash_error);
        }
        const auto get_api = reinterpret_cast<MwAddonGetApiFn>(
            GetProcAddress(module, "MwAddonGetApi"));
        if (get_api == nullptr) {
            FreeLibrary(module);
            return MakeResponse(runtime, session, id, MW_ERROR_ABI, "MwAddonGetApi export is missing");
        }

        auto addon = std::make_unique<AddonState>();
        addon->id = addon_id;
        addon->canonical_path = canonical_path;
        addon->owner_pid = session.owner_pid;
        addon->owner_creation_time = session.owner_creation_time;
        addon->module = module;
        addon->image_sha256 = image_sha256;
        addon->settings = std::move(settings);
        BuildHostApi(*addon);
        MwAddonApi api{};
        api.struct_size = sizeof(api);
        MwStatus api_status = MW_ERROR_ABI;
        try {
            // The ordinary LoadLibraryExW reference keeps the export mapped
            // while its table is validated. Do not make a process-lifetime
            // pin until the complete ABI table has passed validation.
            api_status = get_api(MW_NATIVE_ABI_VERSION, &api);
        } catch (...) {
            api_status = MW_ERROR_ABI;
        }
        constexpr uint32_t kRequiredAddonApiSize =
            static_cast<uint32_t>(offsetof(MwAddonApi, message_received));
        if (api_status != MW_OK || api.struct_size < kRequiredAddonApiSize ||
            api.abi_version != MW_NATIVE_ABI_VERSION || api.name_utf8 == nullptr ||
            api.create_instance == nullptr || api.start == nullptr || api.settings_changed == nullptr || api.stop == nullptr ||
            api.instance_policy > MW_ADDON_INSTANCE_MULTIPLE) {
            FreeLibrary(module);
            return MakeResponse(runtime, session, id, MW_ERROR_ABI, "add-on API table is incompatible or incomplete");
        }
        std::array<const void*, 7> callback_code{
            static_cast<const void*>(module),
            reinterpret_cast<const void*>(get_api),
            reinterpret_cast<const void*>(api.create_instance),
            reinterpret_cast<const void*>(api.start),
            reinterpret_cast<const void*>(api.settings_changed),
            reinterpret_cast<const void*>(api.stop),
            nullptr,
        };
        if (api.struct_size >= sizeof(MwAddonApi) && api.message_received != nullptr) {
            callback_code.back() = reinterpret_cast<const void*>(api.message_received);
        }
        const auto invalid_callback = std::find_if(callback_code.begin(),
            callback_code.end(), [](const void* code) {
                return code != nullptr && !IsImageBackedAddress(code);
            });
        if (invalid_callback != callback_code.end()) {
            const auto callback_index = static_cast<std::size_t>(
                std::distance(callback_code.begin(), invalid_callback));
            FreeLibrary(module);
            return MakeResponse(runtime, session, id, MW_ERROR_ABI,
                "add-on callback table entry " + std::to_string(callback_index) +
                    " must point into committed image code");
        }
        registry_lock.lock();
        for (const auto& [other_id, other] : runtime.addons) {
            (void)other_id;
            if (other->module == module && (other->image_sha256 != image_sha256 ||
                api.instance_policy == MW_ADDON_INSTANCE_SINGLETON)) {
                FreeLibrary(module);
                return MakeResponse(runtime, session, id, MW_ERROR_STATE,
                    "this DLL declares a singleton instance or has a different resident image identity");
            }
        }
        registry_lock.unlock();
        for (const void* code : callback_code) {
            if (code == nullptr) continue;
            if (mw::module_lifetime::PinAddress(code).disposition ==
                mw::module_lifetime::PinDisposition::Failure) {
                FreeLibrary(module);
                return MakeResponse(runtime, session, id, MW_ERROR_ADDON, "could not pin add-on callback code");
            }
        }
        addon->api = api;
        addon->state = AddonStateKind::Stopped;
        addon->owner_alive.store(!session.owner_lost.load(std::memory_order_acquire), std::memory_order_release);
        AddonState* state = addon.get();
        std::unique_lock instance_lock(state->lifecycle_mutex);
        registry_lock.lock();
        runtime.addons.emplace(addon_id, std::move(addon));
        registry_lock.unlock();
        loader_lock.unlock();
        std::string error;
        const MwStatus status = CallStart(*state, &error);
        if (status != MW_OK) {
            SetFailure(*state, status, error);
        }
        return MakeResponse(runtime, session, id, status, std::move(error));
    }

    if (found == runtime.addons.end()) {
        return MakeResponse(runtime, session, id, MW_ERROR_STATE, "addonId is not loaded");
    }
    AddonState& addon = *found->second;
    std::unique_lock instance_lock(addon.lifecycle_mutex, std::try_to_lock);
    if (!instance_lock.owns_lock()) {
        return MakeResponse(runtime, session, id, MW_ERROR_BUSY, "add-on callback is still running");
    }
    registry_lock.unlock();

    if (addon.owner_pid != session.owner_pid ||
        addon.owner_creation_time != session.owner_creation_time) {
        return MakeResponse(runtime, session, id, MW_ERROR_STATE,
            "add-on is owned by a different companion process session");
    }

    if (addon.state == AddonStateKind::Draining &&
        (operation == "activate" || operation == "settings")) {
        return MakeResponse(runtime, session, id, MW_ERROR_STATE,
            "add-on calls are still draining; retry stop before activation or settings");
    }

    if (operation == "prepareSymbols") {
        const auto symbols = request.find("symbols");
        if (symbols == request.end() || !symbols->is_array()) {
            return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "symbols must be an array");
        }
        std::map<std::pair<std::wstring, std::string>, void*> prepared;
        for (const Json& entry : *symbols) {
            std::wstring module_name;
            if (!entry.is_object() || !entry.contains("module") || !entry["module"].is_string() ||
                !entry.contains("name") || !entry["name"].is_string() ||
                !Utf8ToWide(entry["module"].get_ref<const std::string&>(), &module_name)) {
                return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "symbol preparation is malformed");
            }
            HMODULE module = nullptr;
            if (!GetModuleHandleExW(0, module_name.c_str(), &module)) {
                return MakeResponse(runtime, session, id, MW_ERROR_MODULE_NOT_READY, "symbol module is unavailable");
            }
            const auto pin = mw::module_lifetime::PinAddress(module);
            Json actual;
            const bool identified = pin.disposition != mw::module_lifetime::PinDisposition::Failure &&
                SymbolModuleIdentity(module, &actual);
            FreeLibrary(module);
            if (!identified) {
                return MakeResponse(runtime, session, id, MW_ERROR_MODULE_NOT_READY, "symbol module is unavailable");
            }
            for (const char* field : {"base", "size", "machine", "timestamp", "checksum", "pdbGuid", "pdbAge", "pdbFile"}) {
                if (!entry.contains(field) || entry[field] != actual[field]) {
                    return MakeResponse(runtime, session, id, MW_ERROR_STATE, "symbol module identity changed");
                }
            }
            const bool missing = entry.value("missing", false);
            const uint64_t rva = entry.value("rva", uint64_t(0));
            if (!missing && !ExecutableRva(module, rva)) {
                return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "symbol RVA is outside executable module code");
            }
            prepared.emplace(std::make_pair(LowerPath(module_name), entry["name"].get<std::string>()),
                missing ? nullptr : reinterpret_cast<uint8_t*>(module) + rva);
        }
        {
            std::lock_guard symbols_lock(addon.symbols_mutex);
            for (const auto& [key, address] : prepared) {
                addon.resolved_symbols[key] = address;
                addon.pending_symbols.erase(key);
            }
        }
        return MakeResponse(runtime, session, id, MW_OK);
    }

    if (operation == "settings") {
        Json settings;
        if (!ReadSettings(request, &settings)) {
            return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "settings must be a JSON object");
        }
        if (addon.state != AddonStateKind::Active) {
            addon.settings = std::move(settings);
            addon.last_code = MW_OK;
            addon.last_error.clear();
            return MakeResponse(runtime, session, id, MW_OK);
        }
        const std::string settings_json = settings.dump();
        MwStatus status = MW_ERROR_ADDON;
        try {
            status = addon.api.settings_changed(addon.instance_context, settings_json.c_str());
        } catch (...) {
            status = MW_ERROR_ADDON;
        }
        if (status != MW_OK) {
            const std::string error = CallbackError("settings_changed", status);
            SetFailure(addon, status, error);
            return MakeResponse(runtime, session, id, status, error);
        }
        addon.settings = std::move(settings);
        addon.last_code = MW_OK;
        addon.last_error.clear();
        return MakeResponse(runtime, session, id, MW_OK);
    }

    if (operation == "message") {
        if (addon.state != AddonStateKind::Active || !addon.api.message_received) {
            return MakeResponse(runtime, session, id, MW_ERROR_STATE,
                "add-on does not accept messages in its current state");
        }
        const auto message = request.find("message");
        if (message == request.end() || !message->is_object()) {
            return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT,
                "message must be a JSON object");
        }
        const std::string message_json = message->dump();
        MwStatus status = MW_ERROR_ADDON;
        try {
            status = addon.api.message_received(addon.instance_context, message_json.c_str());
        } catch (...) {
            status = MW_ERROR_ADDON;
        }
        if (status != MW_OK) {
            const std::string error = CallbackError("message_received", status);
            SetFailure(addon, status, error);
            return MakeResponse(runtime, session, id, status, error);
        }
        addon.last_code = MW_OK;
        addon.last_error.clear();
        return MakeResponse(runtime, session, id, MW_OK);
    }

    if (operation == "stop") {
        std::string error;
        const MwStatus status = CallStop(addon, true, &error);
        if (status != MW_OK) {
            SetFailure(addon, status, error);
        }
        return MakeResponse(runtime, session, id, status, std::move(error));
    }

    if (operation == "activate") {
        if (addon.state == AddonStateKind::Active) {
            return MakeResponse(runtime, session, id, MW_ERROR_STATE, "add-on is already active");
        }
        if (addon.state != AddonStateKind::Stopped &&
            addon.state != AddonStateKind::AwaitingModule) {
            return MakeResponse(runtime, session, id, MW_ERROR_STATE, "add-on is not in a reactivatable state");
        }
        std::string error;
        const MwStatus status = CallStart(addon, &error);
        if (status != MW_OK) {
            SetFailure(addon, status, error);
        }
        return MakeResponse(runtime, session, id, status, std::move(error));
    }

    return MakeResponse(runtime, session, id, MW_ERROR_ARGUMENT, "unknown operation");
}

bool WriteAll(HANDLE pipe, std::string_view bytes) {
    while (!bytes.empty()) {
        DWORD written = 0;
        const DWORD request = static_cast<DWORD>(
            std::min<std::size_t>(bytes.size(), MAXDWORD));
        if (!WriteFile(pipe, bytes.data(), request, &written, nullptr) || written == 0) {
            return false;
        }
        bytes.remove_prefix(written);
    }
    return true;
}

bool WriteJsonLine(HANDLE pipe, const Json& json) {
    std::string line;
    try {
        line = json.dump();
        line.push_back('\n');
    } catch (...) {
        line = R"({"id":null,"ok":false,"code":8,"error":"failed to serialize response","addons":[]})";
        line.push_back('\n');
    }
    return WriteAll(pipe, line);
}

bool ServeConnectedPipe(HANDLE pipe, Runtime& runtime, WorkerSession& session) {
    std::string pending;
    char buffer[4096];
    while (!session.shutdown_requested.load(std::memory_order_acquire) &&
        !session.owner_lost.load(std::memory_order_acquire)) {
        DWORD read_count = 0;
        if (!ReadFile(pipe, buffer, sizeof(buffer), &read_count, nullptr) || read_count == 0) {
            return GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_NO_DATA;
        }
        try {
            pending.append(buffer, read_count);
        } catch (const std::bad_alloc&) {
            std::lock_guard lifecycle_lock(runtime.registry_mutex);
            WriteJsonLine(pipe, Json{{"id", nullptr}, {"ok", false}, {"code", MW_ERROR_IO},
                {"error", "insufficient memory to buffer protocol request"},
                {"addons", AllAddonStatuses(runtime)}});
            return false;
        }
        std::size_t newline = std::string::npos;
        while ((newline = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, newline);
            pending.erase(0, newline + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            Json response;
            try {
                const Json request = Json::parse(line);
                response = HandleRequest(runtime, session, request);
            } catch (const Json::exception& error) {
                std::lock_guard lifecycle_lock(runtime.registry_mutex);
                response = MakeResponse(runtime, session, nullptr, MW_ERROR_ARGUMENT,
                    std::string("invalid JSON: ") + error.what());
            } catch (...) {
                std::lock_guard lifecycle_lock(runtime.registry_mutex);
                response = MakeResponse(runtime, session, nullptr, MW_ERROR_ADDON,
                    "unexpected native exception while handling request");
            }
            if (!WriteJsonLine(pipe, response)) {
                return false;
            }
            if (session.shutdown_requested.load(std::memory_order_acquire)) {
                return true;
            }
        }
    }
    return true;
}

bool IsValidPipeName(const wchar_t* value, std::wstring* name) {
    if (value == nullptr || name == nullptr) {
        return false;
    }
    const std::size_t length = wcsnlen_s(value, MW_AGENT_PIPE_CAPACITY);
    constexpr std::wstring_view prefix = L"\\\\.\\pipe\\";
    if (length < prefix.size() + 1 || length >= MW_AGENT_PIPE_CAPACITY) {
        return false;
    }
    std::wstring_view view(value, length);
    if (view.substr(0, prefix.size()) != prefix ||
        view.find_first_of(L"\r\n") != std::wstring_view::npos) {
        return false;
    }
    *name = std::wstring(view);
    return true;
}

bool ValidateTargetIdentity(const MwAgentStartConfig& config) {
    if (config.target_pid == 0 || config.target_pid != GetCurrentProcessId()) {
        return false;
    }
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        return false;
    }
    ULARGE_INTEGER actual{};
    actual.LowPart = creation.dwLowDateTime;
    actual.HighPart = creation.dwHighDateTime;
    return actual.QuadPart == config.target_creation_time;
}

bool ValidateOwnerIdentity(const MwAgentStartConfig& config, HANDLE* owner) {
    if (owner == nullptr || config.owner_pid == 0 || config.owner_process_handle == 0) {
        return false;
    }
    HANDLE process = reinterpret_cast<HANDLE>(
        static_cast<uintptr_t>(config.owner_process_handle));
    const DWORD actual_pid = GetProcessId(process);
    if (actual_pid == 0) {
        return false;
    }
    if (actual_pid != config.owner_pid) {
        CloseHandle(process);
        return false;
    }
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        CloseHandle(process);
        return false;
    }
    ULARGE_INTEGER actual{};
    actual.LowPart = creation.dwLowDateTime;
    actual.HighPart = creation.dwHighDateTime;
    if (actual.QuadPart != config.owner_creation_time) {
        CloseHandle(process);
        return false;
    }
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) {
        CloseHandle(process);
        return false;
    }
    *owner = process;
    return true;
}

struct AgentWorkerStart {
    std::wstring pipe_name;
    HANDLE owner_process = nullptr;
    uint32_t owner_pid = 0;
    uint64_t owner_creation_time = 0;
};

struct OwnerMonitorStart {
    WorkerSession* session = nullptr;
    HANDLE owner_process = nullptr;
    HANDLE worker_thread = nullptr;
    HANDLE finished_event = nullptr;
};

std::vector<AddonState*> OwnedAddons(Runtime& runtime, uint32_t pid, uint64_t creation) {
    std::lock_guard registry_lock(runtime.registry_mutex);
    std::vector<AddonState*> owned;
    for (auto& [id, addon] : runtime.addons) {
        (void)id;
        if (addon->owner_pid == pid && addon->owner_creation_time == creation) {
            owned.push_back(addon.get());
        }
    }
    return owned; // States stay resident, so these pointers cannot be invalidated.
}

void DisableOwnedHooks(Runtime& runtime, uint32_t pid, uint64_t creation) {
    for (AddonState* addon : OwnedAddons(runtime, pid, creation)) {
        addon->owner_alive.store(false, std::memory_order_release);
        addon->accepting_hooks.store(false, std::memory_order_release);
        std::lock_guard backend_lock(runtime.backend_mutex);
        for (uint64_t hook_id : addon->hook_ids) {
            const auto found = runtime.hooks.find(hook_id);
            if (found != runtime.hooks.end()) {
                (void)mw::hooks::Disable(reinterpret_cast<ULONG_PTR>(addon), found->second.target);
            }
        }
    }
}

DWORD WINAPI MonitorOwner(void* parameter) {
    std::unique_ptr<OwnerMonitorStart> start(
        static_cast<OwnerMonitorStart*>(parameter));
    HANDLE waits[] = {start->owner_process, start->finished_event};
    const DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (result == WAIT_OBJECT_0) {
        start->session->owner_lost.store(true, std::memory_order_release);
        DisableOwnedHooks(GetRuntime(), start->session->owner_pid,
            start->session->owner_creation_time);
        // Cancellation can race with the worker entering the next synchronous
        // pipe call. Retry until that worker observes shutdown and completes.
        while (WaitForSingleObject(start->finished_event, 10) == WAIT_TIMEOUT) {
            (void)CancelSynchronousIo(start->worker_thread);
        }
    }
    return result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1
        ? ERROR_SUCCESS : GetLastError();
}

void StopOwnedAddons(Runtime& runtime, uint32_t owner_pid,
    uint64_t owner_creation_time) {
    DisableOwnedHooks(runtime, owner_pid, owner_creation_time);
    for (AddonState* addon : OwnedAddons(runtime, owner_pid, owner_creation_time)) {
        const ULONGLONG deadline = GetTickCount64() + 1000;
        for (;;) {
            std::unique_lock instance_lock(addon->lifecycle_mutex, std::try_to_lock);
            if (!instance_lock.owns_lock()) break;
            std::string error;
            const MwStatus status = CallStop(*addon, false, &error);
            if (status != MW_ERROR_DRAIN_PENDING || GetTickCount64() >= deadline) {
                if (status != MW_OK) {
                    OutputDebugStringA("[mw-native-agent] add-on owner-death shutdown did not fully drain\n");
                }
                break;
            }
            Sleep(10);
        }
    }
}

struct ActiveSessionGuard {
    Runtime& runtime;
    uint32_t owner_pid;
    uint64_t owner_creation_time;
    ~ActiveSessionGuard() {
        std::lock_guard lock(runtime.sessions_mutex);
        runtime.active_sessions.erase({owner_pid, owner_creation_time});
    }
};

struct ActiveWorkerGuard {
    Runtime& runtime;
    explicit ActiveWorkerGuard(Runtime& value) : runtime(value) {
        runtime.active_workers.fetch_add(1, std::memory_order_acq_rel);
    }
    ~ActiveWorkerGuard() {
        runtime.active_workers.fetch_sub(1, std::memory_order_acq_rel);
    }
};

struct ActiveOwnerMonitorGuard {
    Runtime& runtime;
    explicit ActiveOwnerMonitorGuard(Runtime& value) : runtime(value) {
        runtime.active_owner_monitors.fetch_add(1, std::memory_order_acq_rel);
    }
    ~ActiveOwnerMonitorGuard() {
        runtime.active_owner_monitors.fetch_sub(1, std::memory_order_acq_rel);
    }
};

void ReleaseSessionRegistration(Runtime& runtime, uint32_t owner_pid,
    uint64_t owner_creation_time) {
    std::lock_guard lock(runtime.sessions_mutex);
    runtime.active_sessions.erase({owner_pid, owner_creation_time});
}

DWORD WINAPI AgentWorker(void* parameter) {
    std::unique_ptr<AgentWorkerStart> start(static_cast<AgentWorkerStart*>(parameter));
    Runtime& runtime = GetRuntime();
    ActiveSessionGuard session_registration{
        runtime, start->owner_pid, start->owner_creation_time};
    ActiveWorkerGuard worker_count(runtime);
    WorkerSession session{};
    session.owner_pid = start->owner_pid;
    session.owner_creation_time = start->owner_creation_time;

    HANDLE finished_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE worker_thread = OpenThread(THREAD_TERMINATE | SYNCHRONIZE,
        FALSE, GetCurrentThreadId());
    if (finished_event == nullptr || worker_thread == nullptr) {
        if (finished_event != nullptr) CloseHandle(finished_event);
        if (worker_thread != nullptr) CloseHandle(worker_thread);
        CloseHandle(start->owner_process);
        return static_cast<DWORD>(MW_ERROR_IO);
    }
    auto* monitor_start = new (std::nothrow) OwnerMonitorStart{
        &session, start->owner_process, worker_thread, finished_event};
    if (monitor_start == nullptr) {
        CloseHandle(finished_event);
        CloseHandle(worker_thread);
        CloseHandle(start->owner_process);
        return static_cast<DWORD>(MW_ERROR_IO);
    }
    HANDLE owner_monitor = CreateThread(nullptr, 0, &MonitorOwner,
        monitor_start, 0, nullptr);
    if (owner_monitor == nullptr) {
        delete monitor_start;
        CloseHandle(finished_event);
        CloseHandle(worker_thread);
        CloseHandle(start->owner_process);
        return static_cast<DWORD>(MW_ERROR_IO);
    }
    ActiveOwnerMonitorGuard monitor_count(runtime);
    runtime.worker_sessions_started.fetch_add(1, std::memory_order_relaxed);

    {
        std::lock_guard lock(runtime.backend_mutex);
        const MH_STATUS status = MH_Initialize();
        if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
            OutputDebugStringA("[mw-native-agent] MinHook initialization failed\n");
            SetEvent(finished_event);
            WaitForSingleObject(owner_monitor, INFINITE);
            CloseHandle(owner_monitor);
            CloseHandle(finished_event);
            CloseHandle(worker_thread);
            CloseHandle(start->owner_process);
            return static_cast<DWORD>(MW_ERROR_HOOK);
        }
        runtime.hook_backend_ready = true;
    }

    while (!session.shutdown_requested.load(std::memory_order_acquire) &&
        !session.owner_lost.load(std::memory_order_acquire)) {
        HANDLE pipe = CreateNamedPipeW(start->pipe_name.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 64 * 1024, 64 * 1024, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            OutputDebugStringA("[mw-native-agent] CreateNamedPipeW failed\n");
            break;
        }
        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        const DWORD connect_error = connected ? ERROR_SUCCESS : GetLastError();
        if (connected || connect_error == ERROR_PIPE_CONNECTED) {
            ServeConnectedPipe(pipe, runtime, session);
            if (!session.owner_lost.load(std::memory_order_acquire)) {
                FlushFileBuffers(pipe);
            }
            DisconnectNamedPipe(pipe);
        } else if (connect_error != ERROR_NO_DATA &&
            connect_error != ERROR_OPERATION_ABORTED) {
            OutputDebugStringA("[mw-native-agent] ConnectNamedPipe failed\n");
        }
        CloseHandle(pipe);
        // One companion process owns one connection. EOF, protocol failure,
        // shutdown, and owner death all converge on the same cleanup path.
        break;
    }

    StopOwnedAddons(runtime, start->owner_pid, start->owner_creation_time);
    {
        std::lock_guard lifecycle_lock(runtime.registry_mutex);
        for (auto& [id, addon] : runtime.addons) {
            (void)id;
            if (addon->owner_pid == start->owner_pid &&
                addon->owner_creation_time == start->owner_creation_time) {
                // The exact companion session has ended. A later session may
                // adopt only this same add-on identity and canonical DLL path.
                addon->owner_pid = 0;
                addon->owner_creation_time = 0;
            }
        }
    }
    SetEvent(finished_event);
    WaitForSingleObject(owner_monitor, INFINITE);
    CloseHandle(owner_monitor);
    CloseHandle(finished_event);
    CloseHandle(worker_thread);
    CloseHandle(start->owner_process);
    return MW_OK;
}

bool CopyStartConfig(void* parameter, MwAgentStartConfig* config) {
    if (parameter == nullptr || config == nullptr) {
        return false;
    }
    __try {
        std::memcpy(config, parameter, sizeof(*config));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

extern "C" MW_EXPORT DWORD WINAPI MwAgentStart(void* parameter) {
    MwAgentStartConfig config{};
    if (!CopyStartConfig(parameter, &config)) {
        return static_cast<DWORD>(MW_ERROR_ARGUMENT);
    }
    if (config.struct_size != sizeof(MwAgentStartConfig) ||
        !ValidateTargetIdentity(config)) {
        return static_cast<DWORD>(MW_ERROR_ARGUMENT);
    }
    HANDLE owner_process = nullptr;
    if (!ValidateOwnerIdentity(config, &owner_process)) {
        return static_cast<DWORD>(MW_ERROR_ARGUMENT);
    }
    std::wstring pipe_name;
    if (!IsValidPipeName(config.pipe_name, &pipe_name)) {
        CloseHandle(owner_process);
        return static_cast<DWORD>(MW_ERROR_ARGUMENT);
    }
    if (mw::module_lifetime::PinAddress(reinterpret_cast<const void*>(&MwAgentStart)).disposition ==
        mw::module_lifetime::PinDisposition::Failure) {
        CloseHandle(owner_process);
        return static_cast<DWORD>(MW_ERROR_ADDON);
    }
    Runtime& runtime = GetRuntime();
    bool inserted = false;
    try {
        std::lock_guard lock(runtime.sessions_mutex);
        inserted = runtime.active_sessions.emplace(
            config.owner_pid, config.owner_creation_time).second;
    } catch (...) {
        CloseHandle(owner_process);
        return static_cast<DWORD>(MW_ERROR_IO);
    }
    if (!inserted) {
        CloseHandle(owner_process);
        return static_cast<DWORD>(MW_ERROR_STATE);
    }
    auto* worker_start = new (std::nothrow) AgentWorkerStart{
        std::move(pipe_name), owner_process, config.owner_pid,
        config.owner_creation_time};
    if (worker_start == nullptr) {
        CloseHandle(owner_process);
        ReleaseSessionRegistration(runtime, config.owner_pid, config.owner_creation_time);
        return static_cast<DWORD>(MW_ERROR_IO);
    }
    HANDLE worker = CreateThread(nullptr, 0, &AgentWorker, worker_start, 0, nullptr);
    if (worker == nullptr) {
        delete worker_start;
        CloseHandle(owner_process);
        ReleaseSessionRegistration(runtime, config.owner_pid, config.owner_creation_time);
        return static_cast<DWORD>(MW_ERROR_IO);
    }
    CloseHandle(worker);
    return MW_OK;
}
