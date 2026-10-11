add_library(mw_native_sdk INTERFACE)
add_library(MyWallpaperNativeEngine::SDK ALIAS mw_native_sdk)
get_filename_component(MW_NATIVE_ENGINE_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
target_include_directories(mw_native_sdk INTERFACE
    "${MW_NATIVE_ENGINE_ROOT}/include"
    "${MW_NATIVE_ENGINE_ROOT}/third_party")
target_compile_features(mw_native_sdk INTERFACE cxx_std_20)
target_compile_definitions(mw_native_sdk INTERFACE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(mw_native_sdk INTERFACE /utf-8 /W4 /permissive-)
