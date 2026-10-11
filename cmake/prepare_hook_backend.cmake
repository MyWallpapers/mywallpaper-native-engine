include_guard(GLOBAL)

if(NOT DEFINED MW_MINHOOK_SOURCE OR MW_MINHOOK_SOURCE STREQUAL "")
    message(FATAL_ERROR "MW_MINHOOK_SOURCE must name the pinned MinHook-Detours checkout")
endif()

set(_mw_backend_source_root "${MW_MINHOOK_SOURCE}/src")
set(_mw_backend_output_root "${CMAKE_BINARY_DIR}/_deps/mw_retained_backend")
set(_mw_source_minhook "${_mw_backend_source_root}/MinHook.c")
set(_mw_source_transaction "${_mw_backend_source_root}/SlimDetours/Transaction.c")
set(_mw_source_trampoline "${_mw_backend_source_root}/SlimDetours/Trampoline.c")

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_mw_source_minhook}"
    "${_mw_source_transaction}"
    "${_mw_source_trampoline}")

function(_mw_read_pinned_backend_source source_path expected_sha256 out_variable)
    if(NOT EXISTS "${source_path}")
        message(FATAL_ERROR "Pinned backend source is missing: ${source_path}")
    endif()

    file(READ "${source_path}" source_text)
    # Git checkouts may use CRLF on Windows; authenticate the same LF content.
    string(REPLACE "\r\n" "\n" source_text "${source_text}")
    string(SHA256 actual_sha256 "${source_text}")
    string(TOLOWER "${actual_sha256}" actual_sha256)
    if(NOT actual_sha256 STREQUAL expected_sha256)
        message(FATAL_ERROR
            "Pinned backend source hash mismatch for ${source_path}: "
            "expected ${expected_sha256}, got ${actual_sha256}")
    endif()

    set(${out_variable} "${source_text}" PARENT_SCOPE)
endfunction()

function(_mw_replace_exact source_variable old_text new_text expected_count label)
    set(source_text "${${source_variable}}")
    string(LENGTH "${old_text}" old_length)
    if(old_length EQUAL 0)
        message(FATAL_ERROR "Internal patch error: empty match for ${label}")
    endif()

    string(REPLACE "${old_text}" "" source_without_match "${source_text}")
    string(LENGTH "${source_text}" source_length)
    string(LENGTH "${source_without_match}" remaining_length)
    math(EXPR removed_length "${source_length} - ${remaining_length}")
    math(EXPR count_remainder "${removed_length} % ${old_length}")
    math(EXPR actual_count "${removed_length} / ${old_length}")
    if(NOT count_remainder EQUAL 0 OR NOT actual_count EQUAL expected_count)
        message(FATAL_ERROR
            "Patch assertion failed for ${label}: expected ${expected_count} exact match(es), "
            "found ${actual_count}")
    endif()

    string(REPLACE "${old_text}" "${new_text}" source_text "${source_text}")
    set(${source_variable} "${source_text}" PARENT_SCOPE)
endfunction()

function(_mw_write_if_changed output_path content_variable)
    if(EXISTS "${output_path}")
        file(READ "${output_path}" existing_text)
    else()
        set(existing_text "")
    endif()

    if(NOT existing_text STREQUAL "${${content_variable}}")
        get_filename_component(output_directory "${output_path}" DIRECTORY)
        file(MAKE_DIRECTORY "${output_directory}")
        file(WRITE "${output_path}" "${${content_variable}}")
    endif()
endfunction()

_mw_read_pinned_backend_source(
    "${_mw_source_minhook}"
    "9b5731f146d78a7275e789d9a74b3a8858292a9a22474fca8777f7035a0b736c"
    _mw_minhook)
_mw_read_pinned_backend_source(
    "${_mw_source_transaction}"
    "986593c721417606a243841daf001c34389df7cb1da0c71da1a89b25e66d4e9c"
    _mw_transaction)
_mw_read_pinned_backend_source(
    "${_mw_source_trampoline}"
    "c9bbf26bd51d290ece28cb11101102d726aad24b9c0b31520b377f4da5011fee"
    _mw_trampoline)

_mw_replace_exact(_mw_minhook
    [=[static void FreeHookTrampolineIfNeeded(PHOOK_ENTRY pHook)
{
    if (pHook->pTrampolineToFree)
    {
        SlimDetoursFreeTrampoline(pHook->pTrampolineToFree);
        pHook->pTrampolineToFree = NULL;
    }
}]=]
    [=[static void RetireHookTrampolineIfNeeded(PHOOK_ENTRY pHook)
{
    // Retired trampolines may still be reachable from a live hook chain or call frame.
    pHook->pTrampolineToFree = NULL;
}]=]
    1 "MinHook trampoline retirement helper")
_mw_replace_exact(_mw_minhook
    [=[FreeHookTrampolineIfNeeded]=]
    [=[RetireHookTrampolineIfNeeded]=]
    2 "MinHook trampoline retirement call sites")
_mw_replace_exact(_mw_minhook
    [=[pHookIter->pTargetOrTrampoline = *pHookIter->ppOriginal;]=]
    [=[pHookIter->pTargetOrTrampoline = InterlockedCompareExchangePointer(
                            (PVOID volatile*)pHookIter->ppOriginal, NULL, NULL);]=]
    1 "MinHook shared ppOriginal read")
_mw_replace_exact(_mw_minhook
    [=[*ppOriginal = pTarget;]=]
    [=[InterlockedExchangePointer((PVOID volatile*)ppOriginal, pTarget);]=]
    1 "MinHook ppOriginal initialization store")

# Release borrowed creator storage after the one physical installation. The
# underlying record stays enabled and uses its own storage for process lifetime.
string(APPEND _mw_minhook [=[

void MwBackendReleaseOriginalStorage(ULONG_PTR identity, LPVOID target)
{
    if (!EnterEngine()) return;
    UINT pos = FindHookEntry(identity, target, 0);
    if (pos != INVALID_HOOK_POS)
    {
        PHOOK_ENTRY hook = &g_hooks.pItems[pos];
        if (hook->ppOriginal)
        {
            hook->pTargetOrTrampoline = InterlockedCompareExchangePointer(
                (PVOID volatile*)hook->ppOriginal, NULL, NULL);
            hook->ppOriginal = NULL;
        }
    }
    LeaveEngine();
}
]=])

_mw_replace_exact(_mw_transaction
    [=[#include "SlimDetours.inl"]=]
    [=[#include "SlimDetours.inl"
#include "hook_backend_policy.h"]=]
    1 "Transaction policy include")
_mw_replace_exact(_mw_transaction
    [=[*o->ppbPointer = o->pTrampoline->rbCode;]=]
    [=[InterlockedExchangePointer((PVOID volatile*)o->ppbPointer, o->pTrampoline->rbCode);]=]
    1 "Transaction ppOriginal attach store")
_mw_replace_exact(_mw_transaction
    [=[*o->ppbPointer = o->pbTarget;]=]
    [=[InterlockedExchangePointer((PVOID volatile*)o->ppbPointer, o->pbTarget);]=]
    1 "Transaction ppOriginal detach store")
_mw_replace_exact(_mw_transaction
    [=[            o->pTrampoline->pbDetour = o->pTrampoline->rbCode;]=]
    [=[            MwBackendPolicyNoteRetiredTrampoline();
            o->pTrampoline->pbDetour = o->pTrampoline->rbCode;]=]
    1 "Transaction retired trampoline counter")

_mw_replace_exact(_mw_trampoline
    [=[#include "SlimDetours.inl"]=]
    [=[#include "SlimDetours.inl"
#include "hook_backend_policy.h"]=]
    1 "Trampoline policy include")
string(APPEND _mw_trampoline [=[

// The caller serializes this query with hook backend operations.
uint64_t MwBackendTrampolineRegionCount(void)
{
    uint64_t count = 0;
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext)
    {
        ++count;
    }
    return count;
}

uint64_t MwBackendTrampolineSlotBytes(void)
{
    return (uint64_t)sizeof(DETOUR_TRAMPOLINE);
}
]=])

set(MW_PATCHED_MINHOOK_SOURCE "${_mw_backend_output_root}/MinHook.c")
set(MW_PATCHED_TRANSACTION_SOURCE "${_mw_backend_output_root}/Transaction.c")
set(MW_PATCHED_TRAMPOLINE_SOURCE "${_mw_backend_output_root}/Trampoline.c")

_mw_write_if_changed("${MW_PATCHED_MINHOOK_SOURCE}" _mw_minhook)
_mw_write_if_changed("${MW_PATCHED_TRANSACTION_SOURCE}" _mw_transaction)
_mw_write_if_changed("${MW_PATCHED_TRAMPOLINE_SOURCE}" _mw_trampoline)
