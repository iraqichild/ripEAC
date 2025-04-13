#define WIN32_MEAN_AND_LEAN
#include <windows.h>
#include "lazy.hpp"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

EXTERN_DLL_EXPORT void DllEntry(...)
{
	AllocConsole();
}

