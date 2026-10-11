#ifndef MW_NATIVE_HOOK_BACKEND_POLICY_H
#define MW_NATIVE_HOOK_BACKEND_POLICY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The caller holds the agent's backend mutex while reading backend region state. */
uint64_t MwBackendRetiredTrampolineCount(void);
uint64_t MwBackendTrampolineRegionCount(void);
uint64_t MwBackendTrampolineSlotBytes(void);

/* Called by the patched transaction backend when a trampoline becomes a bypass stub. */
void MwBackendPolicyNoteRetiredTrampoline(void);

/* Private, pinned x64 SlimDetours bridge. The caller serializes backend writes. */
void* MwBackendResidentRoute(void* original);
int MwBackendSetResidentRoute(void* original, void* route);
void MwBackendReleaseOriginalStorage(uintptr_t identity, void* target);

#ifdef __cplusplus
}
#endif

#endif /* MW_NATIVE_HOOK_BACKEND_POLICY_H */
