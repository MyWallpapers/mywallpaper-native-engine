#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" __declspec(dllexport) __declspec(noinline) int __cdecl MwFixtureLate(int value) {
    volatile int first = value;
    volatile int second = first;
    volatile int third = second;
    return third;
}
