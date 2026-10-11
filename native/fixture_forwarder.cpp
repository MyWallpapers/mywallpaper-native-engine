#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// The fixture export is forwarded by the PE loader, not by an executable stub.
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
