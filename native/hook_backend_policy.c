#include "SlimDetours.inl"
#include "hook_backend_policy.h"

__declspec(align(8)) static volatile LONG64 g_retiredTrampolineCount = 0;

void MwBackendPolicyNoteRetiredTrampoline(void)
{
    InterlockedIncrement64(&g_retiredTrampolineCount);
}

uint64_t MwBackendRetiredTrampolineCount(void)
{
    return (uint64_t)InterlockedCompareExchange64(&g_retiredTrampolineCount, 0, 0);
}

_STATIC_ASSERT(FIELD_OFFSET(DETOUR_TRAMPOLINE, rbCode) == 0);
_STATIC_ASSERT(FIELD_OFFSET(DETOUR_TRAMPOLINE, pbDetour) % sizeof(void*) == 0);
_STATIC_ASSERT(sizeof(DETOUR_TRAMPOLINE) == 104);

LPVOID MwBackendResidentRoute(LPVOID original)
{
    PDETOUR_TRAMPOLINE trampoline = original;
    // This read occurs under the adapter mutex after physical installation.
    // InterlockedCompareExchangePointer would require write access even when
    // used as a read; the trampoline region is normally executable/read-only.
    return *(PVOID volatile*)&trampoline->pbDetour;
}

BOOL MwBackendSetResidentRoute(LPVOID original, LPVOID route)
{
    PDETOUR_TRAMPOLINE trampoline = original;
    DWORD oldProtection, ignored;
    // The existing rbCodeIn jump reads this aligned cell. Its instructions
    // and original continuation are never rewritten by logical stop/restart.
    if (!VirtualProtect(&trampoline->pbDetour, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtection))
        return FALSE;
    PVOID previous = InterlockedExchangePointer((PVOID volatile*)&trampoline->pbDetour, route);
    if (!VirtualProtect(&trampoline->pbDetour, sizeof(void*), oldProtection, &ignored))
    {
        InterlockedExchangePointer((PVOID volatile*)&trampoline->pbDetour, previous);
        VirtualProtect(&trampoline->pbDetour, sizeof(void*), oldProtection, &ignored);
        return FALSE;
    }
    return TRUE;
}
