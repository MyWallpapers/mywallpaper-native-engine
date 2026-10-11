// MIT SDK launcher. The engine implementation stays in the shared runtime DLL.
#include <mw_native_sdk.hpp>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace {
std::wstring Environment(const wchar_t* name) {
    const DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (!needed) return {};
    std::wstring value(needed, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
    if (!written || written >= needed) throw std::runtime_error("environment changed during lookup");
    value.resize(written);
    return value;
}
const wchar_t* Architecture() {
#if defined(_M_ARM64)
    return L"arm64";
#elif defined(_M_X64)
    return L"x64";
#elif defined(_M_IX86)
    return L"x86";
#else
#error Unsupported native architecture
#endif
}
}

int wmain(int argc, wchar_t** argv) {
    try {
        std::filesystem::path bundle;
        if (argc == 3 && std::wstring_view(argv[1]) == L"--bundle") {
            bundle = std::filesystem::canonical(argv[2]);
        } else if (argc == 1) {
            std::vector<wchar_t> executable(32768);
            const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
            if (!length || length == executable.size()) throw std::runtime_error("cannot locate SDK launcher");
            bundle = std::filesystem::path(std::wstring(executable.data(), length)).parent_path();
        } else {
            throw std::runtime_error("Usage: companion [--bundle ABSOLUTE_ADDON_DIRECTORY]");
        }
        std::ifstream input(bundle / L"mywallpaper-native-engine.json");
        if (!input) throw std::runtime_error("mywallpaper-native-engine.json is missing beside the launcher");
        const auto descriptor = nlohmann::json::parse(input);
        auto home = Environment(L"MW_NATIVE_ENGINE_HOME");
        if (descriptor.contains("engineDirectory")) {
            if (!mw_native::Utf8ToWide(descriptor.at("engineDirectory").get<std::string>(), &home))
                throw std::runtime_error("engineDirectory must be valid UTF-8");
        }
        if (home.empty()) {
            home = Environment(L"LOCALAPPDATA");
            if (home.empty()) throw std::runtime_error("Set MW_NATIVE_ENGINE_HOME to the installed runtime");
            home = (std::filesystem::path(home) / L"MyWallpaper" / L"NativeEngine").wstring();
        }
        if (!std::filesystem::path(home).is_absolute()) throw std::runtime_error("engine directory must be absolute");
        const auto root = std::filesystem::canonical(home);
        if (!SetEnvironmentVariableW(L"MW_NATIVE_ENGINE_HOME", root.c_str()))
            throw std::runtime_error("cannot configure shared engine directory");
        const auto library = root / Architecture() / L"mw-native-runtime.dll";
        const HMODULE runtime = LoadLibraryExW(library.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!runtime) throw std::runtime_error("matching shared mw-native-runtime.dll is unavailable (Windows error " + std::to_string(GetLastError()) + ")");
        using Run = int(__cdecl*)(uint32_t, const wchar_t*, size_t);
        const auto run = reinterpret_cast<Run>(GetProcAddress(runtime, "MwNativeEngineRun"));
        if (!run) throw std::runtime_error("shared runtime does not export MwNativeEngineRun");
        // The DLL and its worker threads remain alive until process exit.
        const std::wstring path = bundle.wstring();
        return run(MW_NATIVE_ABI_VERSION, path.c_str(), path.size());
    } catch (const std::exception& error) {
        std::cerr << nlohmann::json({{"source", "mywallpaper-native-engine"}, {"schemaVersion", 1},
            {"severity", "error"}, {"code", "shared_engine_unavailable"}, {"operation", "initialize"},
            {"message", error.what()}}).dump() << '\n';
        return 2;
    }
}
