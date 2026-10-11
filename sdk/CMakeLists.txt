add_library(mw_native_sdk INTERFACE)
add_library(MyWallpaperNativeEngine::SDK ALIAS mw_native_sdk)
get_filename_component(MW_NATIVE_ENGINE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
target_include_directories(mw_native_sdk INTERFACE
    "$<BUILD_INTERFACE:${MW_NATIVE_ENGINE_ROOT}/include>"
    "$<BUILD_INTERFACE:${MW_NATIVE_ENGINE_ROOT}/third_party>"
    "$<INSTALL_INTERFACE:include>")
set_target_properties(mw_native_sdk PROPERTIES EXPORT_NAME SDK)
target_compile_features(mw_native_sdk INTERFACE cxx_std_20)
target_compile_definitions(mw_native_sdk INTERFACE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(mw_native_sdk INTERFACE /utf-8 /W4 /permissive-)

include(CMakePackageConfigHelpers)
install(TARGETS mw_native_sdk EXPORT MyWallpaperNativeEngineTargets)
install(FILES "${MW_NATIVE_ENGINE_ROOT}/include/mw_native_sdk.h"
    "${MW_NATIVE_ENGINE_ROOT}/include/mw_native_sdk.hpp"
    "${MW_NATIVE_ENGINE_ROOT}/include/mw_call_gate.hpp" DESTINATION include)
install(DIRECTORY "${MW_NATIVE_ENGINE_ROOT}/third_party/nlohmann" DESTINATION include
    FILES_MATCHING PATTERN "*.hpp")
install(EXPORT MyWallpaperNativeEngineTargets NAMESPACE MyWallpaperNativeEngine::
    DESTINATION lib/cmake/MyWallpaperNativeEngine)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/MyWallpaperNativeEngineConfig.cmake"
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/MyWallpaperNativeEngineTargets.cmake\")\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/MyWallpaperNativeAddon.cmake\")\n")
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/MyWallpaperNativeEngineConfigVersion.cmake"
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion ARCH_INDEPENDENT)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/MyWallpaperNativeEngineConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/MyWallpaperNativeEngineConfigVersion.cmake"
    DESTINATION lib/cmake/MyWallpaperNativeEngine)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/MyWallpaperNativeAddon.cmake"
    DESTINATION lib/cmake/MyWallpaperNativeEngine)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/launcher.cpp"
    DESTINATION share/mywallpaper-native-sdk)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/examples/" DESTINATION examples)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tools/" DESTINATION tools)
install(FILES "${MW_NATIVE_ENGINE_ROOT}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md"
    DESTINATION .)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md" DESTINATION .)
install(FILES "${MW_NATIVE_ENGINE_ROOT}/third_party/nlohmann/LICENSE.MIT"
    DESTINATION notices RENAME nlohmann-json-LICENSE.MIT)
install(FILES "${MW_NATIVE_ENGINE_ROOT}/LICENSE" "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md"
    DESTINATION examples/settings-hook)
install(FILES "${MW_NATIVE_ENGINE_ROOT}/third_party/nlohmann/LICENSE.MIT"
    DESTINATION examples/settings-hook/notices RENAME nlohmann-json-LICENSE.MIT)
