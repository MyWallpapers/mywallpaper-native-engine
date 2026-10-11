cmake_minimum_required(VERSION 3.24)
project(MyWallpaperNativeEngine VERSION 0.2.0 LANGUAGES C CXX)

set(CMAKE_SUPPRESS_REGENERATION ON)
if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "The engine requires Windows and MSVC (x86, x64, ARM64)")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_compile_options("/Brepro" "/experimental:deterministic"
    "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}=.")
add_link_options("/Brepro")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
foreach(config Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${config}" config_upper)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper} "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper} "${CMAKE_BINARY_DIR}/bin")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper} "${CMAKE_BINARY_DIR}/lib")
endforeach()

set(MW_MINHOOK_SOURCE "" CACHE PATH "Source tree matching the vendored MinHook-Detours pin")
if(NOT MW_MINHOOK_SOURCE)
    set(MW_MINHOOK_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook-detours")
endif()

# Build from the bundled snapshot by default. An alternate development path is
# accepted only if every source/support file and the upstream root license
# match the checked-in manifest; a three-file patch hash alone is insufficient.
set(_mw_minhook_manifest "${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook-detours.SHA256SUMS")
if(NOT EXISTS "${_mw_minhook_manifest}")
    message(FATAL_ERROR "The vendored MinHook-Detours source manifest is missing")
endif()
file(STRINGS "${_mw_minhook_manifest}" _mw_minhook_manifest_entries)
file(GLOB_RECURSE _mw_minhook_files LIST_DIRECTORIES FALSE
    "${MW_MINHOOK_SOURCE}/src/*")
list(APPEND _mw_minhook_files "${MW_MINHOOK_SOURCE}/LICENSE")
list(LENGTH _mw_minhook_manifest_entries _mw_manifest_count)
list(LENGTH _mw_minhook_files _mw_source_file_count)
if(NOT _mw_manifest_count EQUAL _mw_source_file_count)
    message(FATAL_ERROR
        "MinHook-Detours source file inventory mismatch: expected ${_mw_manifest_count}, "
        "found ${_mw_source_file_count}")
endif()
foreach(_mw_source_file IN LISTS _mw_minhook_files)
    if(NOT EXISTS "${_mw_source_file}")
        message(FATAL_ERROR "Pinned MinHook-Detours source is missing: ${_mw_source_file}")
    endif()
    file(SHA256 "${_mw_source_file}" _mw_source_sha256)
    file(RELATIVE_PATH _mw_relative_path "${MW_MINHOOK_SOURCE}" "${_mw_source_file}")
    string(REPLACE "\\" "/" _mw_relative_path "${_mw_relative_path}")
    set(_mw_expected_entry "${_mw_source_sha256}  ${_mw_relative_path}")
    if(NOT _mw_expected_entry IN_LIST _mw_minhook_manifest_entries)
        message(FATAL_ERROR "Pinned MinHook-Detours file changed or is unlisted: ${_mw_relative_path}")
    endif()
endforeach()

add_subdirectory(sdk)
include(cmake/prepare_hook_backend.cmake)
set(mh "${MW_MINHOOK_SOURCE}/src")
add_library(mw_native_hook_backend STATIC
    "${MW_PATCHED_MINHOOK_SOURCE}"
    "${mh}/SlimDetours/Disassembler.c"
    "${mh}/SlimDetours/InlineHook.c"
    "${mh}/SlimDetours/Instruction.c"
    "${mh}/SlimDetours/Memory.c"
    "${mh}/SlimDetours/Thread.c"
    "${MW_PATCHED_TRAMPOLINE_SOURCE}"
    "${MW_PATCHED_TRANSACTION_SOURCE}"
    "${MW_RESIDENT_POLICY_SOURCE}")
target_include_directories(mw_native_hook_backend PUBLIC "${mh}")
target_include_directories(mw_native_hook_backend PRIVATE "${mh}/phnt" "${mh}/SlimDetours" native)
target_compile_options(mw_native_hook_backend PRIVATE /std:clatest /utf-8 /W4 /permissive- /Brepro)
target_link_libraries(mw_native_hook_backend PUBLIC ntdll)

add_library(mw_native_agent SHARED native/agent.cpp native/module_lifetime.cpp native/resident_hooks.cpp)
target_link_libraries(mw_native_agent PRIVATE mw_native_sdk mw_native_hook_backend bcrypt)
target_compile_options(mw_native_agent PRIVATE /utf-8 /W4 /permissive- /Brepro)
target_link_options(mw_native_agent PRIVATE /Brepro)
set_target_properties(mw_native_agent PROPERTIES OUTPUT_NAME "mw-native-agent")
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    file(WRITE "${CMAKE_BINARY_DIR}/agent-exports.def" "EXPORTS\nMwAgentStart=_MwAgentStart@4\n")
    target_sources(mw_native_agent PRIVATE "${CMAKE_BINARY_DIR}/agent-exports.def")
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(mw_native_fixture native/fixture.cpp)
    target_link_libraries(mw_native_fixture PRIVATE mw_native_sdk user32)
    target_compile_options(mw_native_fixture PRIVATE /Ob0 /Z7 /utf-8 /W4 /permissive- /Brepro)
    set_target_properties(mw_native_fixture PROPERTIES OUTPUT_NAME "mw-native-fixture")
    target_link_options(mw_native_fixture PRIVATE /DEBUG:FULL /OPT:NOICF /Brepro)

    add_library(mw_native_instance_fixture SHARED native/instance_fixture_addon.cpp)
    target_link_libraries(mw_native_instance_fixture PRIVATE mw_native_sdk)
    target_compile_options(mw_native_instance_fixture PRIVATE /utf-8 /W4 /permissive-)
    set_target_properties(mw_native_instance_fixture PROPERTIES OUTPUT_NAME "mw-native-instance-fixture")

    add_library(mw_native_fixture_module SHARED native/fixture_module.cpp)
    target_link_libraries(mw_native_fixture_module PRIVATE mw_native_sdk)
    target_compile_options(mw_native_fixture_module PRIVATE /Ob0 /utf-8 /W4 /permissive- /Brepro)
    target_link_options(mw_native_fixture_module PRIVATE /FUNCTIONPADMIN:16 /Brepro)

    add_library(mw_native_fixture_forwarder SHARED native/fixture_forwarder.cpp native/fixture_forwarder.def)
    target_link_libraries(mw_native_fixture_forwarder PRIVATE mw_native_sdk mw_native_fixture_module)
    target_compile_options(mw_native_fixture_forwarder PRIVATE /utf-8 /W4 /permissive- /Brepro)
    target_link_options(mw_native_fixture_forwarder PRIVATE /Brepro)

    add_library(mw_native_session_fixture_a SHARED native/session_fixture_addon.cpp)
    target_link_libraries(mw_native_session_fixture_a PRIVATE mw_native_sdk)
    target_compile_definitions(mw_native_session_fixture_a PRIVATE
        MW_FIXTURE_ADDON_NAME="session-a" MW_FIXTURE_EXPORT="MwFixtureCompute" MW_FIXTURE_DELTA=1)
    target_compile_options(mw_native_session_fixture_a PRIVATE /utf-8 /W4 /permissive- /Brepro)
    set_target_properties(mw_native_session_fixture_a PROPERTIES OUTPUT_NAME "mw-native-session-a")
    target_link_options(mw_native_session_fixture_a PRIVATE /Brepro)

    add_library(mw_native_session_fixture_b SHARED native/session_fixture_addon.cpp)
    target_link_libraries(mw_native_session_fixture_b PRIVATE mw_native_sdk)
    target_compile_definitions(mw_native_session_fixture_b PRIVATE
        MW_FIXTURE_ADDON_NAME="session-b" MW_FIXTURE_EXPORT="MwFixtureSecondary" MW_FIXTURE_DELTA=2 MW_FIXTURE_REJECT_SETTING=1)
    target_compile_options(mw_native_session_fixture_b PRIVATE /utf-8 /W4 /permissive- /Brepro)
    set_target_properties(mw_native_session_fixture_b PROPERTIES OUTPUT_NAME "mw-native-session-b")
    target_link_options(mw_native_session_fixture_b PRIVATE /Brepro)

    add_library(mw_native_invalid_fixture_addon SHARED native/session_fixture_addon.cpp)
    target_link_libraries(mw_native_invalid_fixture_addon PRIVATE mw_native_sdk)
    target_compile_definitions(mw_native_invalid_fixture_addon PRIVATE
        MW_FIXTURE_ADDON_NAME="invalid-abi" MW_FIXTURE_EXPORT="MwFixtureCompute"
        MW_FIXTURE_DELTA=3 MW_FIXTURE_INVALID_ABI=1)
    target_compile_options(mw_native_invalid_fixture_addon PRIVATE /utf-8 /W4 /permissive- /Brepro)
    set_target_properties(mw_native_invalid_fixture_addon PROPERTIES OUTPUT_NAME "mw-native-invalid-addon")
    target_link_options(mw_native_invalid_fixture_addon PRIVATE /Brepro)

    add_library(mw_native_invalid_callback_fixture_addon SHARED native/session_fixture_addon.cpp)
    target_link_libraries(mw_native_invalid_callback_fixture_addon PRIVATE mw_native_sdk)
    target_compile_definitions(mw_native_invalid_callback_fixture_addon PRIVATE
        MW_FIXTURE_ADDON_NAME="invalid-callback" MW_FIXTURE_EXPORT="MwFixtureCompute"
        MW_FIXTURE_DELTA=3 MW_FIXTURE_INVALID_CALLBACK=1)
    target_compile_options(mw_native_invalid_callback_fixture_addon PRIVATE /utf-8 /W4 /permissive- /Brepro)
    set_target_properties(mw_native_invalid_callback_fixture_addon PROPERTIES OUTPUT_NAME "mw-native-invalid-callback-addon")
    target_link_options(mw_native_invalid_callback_fixture_addon PRIVATE /Brepro)

    add_executable(mw_native_module_lifetime_tests native/module_lifetime_tests.cpp native/module_lifetime.cpp)
    target_link_libraries(mw_native_module_lifetime_tests PRIVATE mw_native_sdk)
    add_executable(mw_native_call_gate_tests native/call_gate_tests.cpp)
    target_link_libraries(mw_native_call_gate_tests PRIVATE mw_native_sdk)
    add_executable(mw_native_backend_contract_tests native/backend_contract_tests.cpp native/resident_hooks.cpp)
    target_link_libraries(mw_native_backend_contract_tests PRIVATE mw_native_sdk mw_native_hook_backend psapi)
    target_compile_options(mw_native_backend_contract_tests PRIVATE /Ob0 /utf-8 /W4 /permissive- /Brepro)
    target_link_options(mw_native_backend_contract_tests PRIVATE /OPT:NOICF /FUNCTIONPADMIN:16 /Brepro)
    add_executable(mw_native_resident_reuse_tests native/resident_reuse_tests.cpp native/resident_hooks.cpp)
    target_link_libraries(mw_native_resident_reuse_tests PRIVATE mw_native_sdk mw_native_hook_backend)
    target_compile_options(mw_native_resident_reuse_tests PRIVATE /Ob0 /utf-8 /W4 /permissive- /Brepro)
    target_link_options(mw_native_resident_reuse_tests PRIVATE /OPT:NOICF /Brepro)

    add_test(NAME mw_native_module_lifetime COMMAND mw_native_module_lifetime_tests)
    add_test(NAME mw_native_call_gate COMMAND mw_native_call_gate_tests)
    add_test(NAME mw_native_backend_contract COMMAND mw_native_backend_contract_tests)
    add_test(NAME mw_native_resident_reuse COMMAND mw_native_resident_reuse_tests)
endif()

# Carry complete upstream notices alongside redistributable build artifacts.
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/bin/notices")
configure_file("${MW_MINHOOK_SOURCE}/LICENSE" "${CMAKE_BINARY_DIR}/bin/notices/minhook-detours-LICENSE" COPYONLY)
configure_file("${mh}/SlimDetours/LICENSE" "${CMAKE_BINARY_DIR}/bin/notices/SlimDetours-LICENSE" COPYONLY)
configure_file("${mh}/phnt/LICENSE" "${CMAKE_BINARY_DIR}/bin/notices/phnt-LICENSE" COPYONLY)
configure_file(third_party/nlohmann/LICENSE.MIT "${CMAKE_BINARY_DIR}/bin/notices/nlohmann-json-LICENSE.MIT" COPYONLY)
configure_file(THIRD_PARTY_NOTICES.md "${CMAKE_BINARY_DIR}/bin/THIRD_PARTY_NOTICES.md" COPYONLY)
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/rust-licenses/"
    DESTINATION "${CMAKE_BINARY_DIR}/bin/notices/rust-licenses")
