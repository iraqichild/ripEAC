#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "lazy.hpp"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

void Main()
{
    AllocConsole();
    SetConsoleTitle(L"ripEac");
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    printf("hello from ripEAC \n");

}

EXTERN_DLL_EXPORT void DllEntry(...)
{
    HANDLE hThread = CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), nullptr, NULL, NULL);
    if (hThread)
        CloseHandle(hThread);
}