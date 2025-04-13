#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "lazy.hpp"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

EXTERN_DLL_EXPORT void DllEntry()
{
   MessageBoxW(NULL, L"hello from ripEAC", L"ripEAC", MB_OK);
}
