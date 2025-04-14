#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "lazy.hpp"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

VOID Allocate()
{
    AttachConsole(ATTACH_PARENT_PROCESS);
   // if (GetConsoleWindow() == nullptr) {
   //     if (!AllocConsole()) {
   //         MessageBoxA(nullptr, "Unable to allocate console.", "Error", MB_ICONERROR);
   //
   //         return;
   //     }
   //
   //     // sometimes the game has hidden the console
   //     ShowWindow(GetConsoleWindow(), SW_SHOW);
   //
   //     FILE* dummy;
   //     freopen_s(&dummy, "CONIN$", "r", stdin);
   //     freopen_s(&dummy, "CONOUT$", "w", stderr);
   //     freopen_s(&dummy, "CONOUT$", "w", stdout);
   // }
}

EXTERN_DLL_EXPORT void DllEntry()
{
    __try {
        Allocate();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Allocate();
        return;
    }
}
