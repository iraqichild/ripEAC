#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "lazy.hpp"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)

EXTERN_DLL_EXPORT void DllEntry(...)
{
   //HANDLE hThread = CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), nullptr, NULL, NULL);
   //if (hThread)
   //    CloseHandle(hThread);

    //AllocConsole();
    //SetConsoleTitle(L"ripEac");
    //FILE* fp;
    //freopen_s(&fp, "CONOUT$", "w", stdout);
    //
    //printf("hello from ripEAC \n");

    MessageBoxW(NULL, L"hello from ripEAC", L"ripEAC", MB_OK);
}

#pragma once
#include <cstdint>
#include <type_traits>

#define SEED ((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 + \
              (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 + \
              (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)


constexpr uint32_t LinearCongruentGenerator(int rounds) {
    return 1013904223 + 1664525 * ((rounds > 0)
        ? LinearCongruentGenerator(rounds - 1)
        : SEED & 0xFFFFFFFF);
}

#define RANDOM(Min, Max) (Min + (LinearCongruentGenerator(10) % (Max - Min + 1)))

template <size_t Size>
class ByteCrypter {
private:
    uint8_t encrypted[Size];

    static constexpr uint8_t EncryptByte(uint8_t byte, size_t index) {
        return byte ^ (RANDOM(0, 255) + index) & 0xFF;
    }

public:
    template <typename T>
    constexpr ByteCrypter(const T(&data)[Size]) {
        for (size_t i = 0; i < Size; ++i) {
            encrypted[i] = EncryptByte(static_cast<uint8_t>(data[i]), i);
        }
    }

    void decrypt(uint8_t* output) const {
        for (size_t i = 0; i < Size; ++i) {
            output[i] = encrypted[i] ^ (RANDOM(0, 255) + i) & 0xFF;
        }
    }

    constexpr size_t size() const { return Size; }
};

#define CRYPT(...) \
    ([]() { \
        constexpr unsigned char data[] = {__VA_ARGS__}; \
        return ByteCrypter<sizeof(data) / sizeof(data[0])>(data); \
    }())

static const auto encrypted_driver = CRYPT(0x01, 0x02, 0x03, 0x04, 0x00);

void example() {
    uint8_t decrypted[encrypted_driver.size()];
    encrypted_driver.decrypt(decrypted);

}