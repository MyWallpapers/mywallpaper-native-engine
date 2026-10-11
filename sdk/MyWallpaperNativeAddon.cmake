# Installed SDK only: never compile or copy private engine sources into an add-on.
function(mywallpaper_native_addon target)
    cmake_parse_arguments(MW "" "DESCRIPTOR;BUNDLE_DIRECTORY" "SOURCES" ${ARGN})
    if(NOT WIN32 OR NOT MSVC OR NOT MW_SOURCES OR NOT MW_DESCRIPTOR OR NOT MW_BUNDLE_DIRECTORY)
        message(FATAL_ERROR "mywallpaper_native_addon requires Windows/MSVC, SOURCES, DESCRIPTOR and BUNDLE_DIRECTORY")
    endif()
    add_library(${target} SHARED ${MW_SOURCES})
    target_link_libraries(${target} PRIVATE MyWallpaperNativeEngine::SDK)
    set_target_properties(${target} PROPERTIES OUTPUT_NAME addon
        RUNTIME_OUTPUT_DIRECTORY "${MW_BUNDLE_DIRECTORY}")
    add_executable(${target}_companion "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../../share/mywallpaper-native-sdk/launcher.cpp")
    target_link_libraries(${target}_companion PRIVATE MyWallpaperNativeEngine::SDK)
    set_target_properties(${target}_companion PROPERTIES OUTPUT_NAME companion
        RUNTIME_OUTPUT_DIRECTORY "${MW_BUNDLE_DIRECTORY}")
    foreach(configuration Debug Release RelWithDebInfo MinSizeRel)
        string(TOUPPER "${configuration}" upper)
        set_target_properties(${target} ${target}_companion PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_${upper} "${MW_BUNDLE_DIRECTORY}")
    endforeach()
    file(MAKE_DIRECTORY "${MW_BUNDLE_DIRECTORY}")
    configure_file("${MW_DESCRIPTOR}" "${MW_BUNDLE_DIRECTORY}/mywallpaper-native-engine.json" COPYONLY)
endfunction()
