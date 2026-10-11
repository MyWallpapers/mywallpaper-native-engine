// Compile independently of the engine tree to exercise the installed SDK.
#include <mw_native_sdk.hpp>
#include <mw_call_gate.hpp>
#include <nlohmann/json.hpp>

extern "C" MW_EXPORT MwStatus MW_CALL MwAddonGetApi(uint32_t version, MwAddonApi* api) {
    if (version != MW_NATIVE_ABI_VERSION || !api) return MW_ERROR_ABI;
    const auto settings = nlohmann::json::parse("{}");
    return settings.is_object() ? MW_OK : MW_ERROR_ARGUMENT;
}
