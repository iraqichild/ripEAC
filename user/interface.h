#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>

#define IOCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

class Interface {
public:
    bool attach(const std::wstring& process_name);
    bool detach();

    bool virtual_alloc(void** base_address, std::size_t* region_size,
        std::uint32_t allocation_type, std::uint32_t protection_type);

    bool virtual_free(void** base_address, std::size_t* region_size,
        std::uint32_t free_type);
    bool read_memory(void* address, void* buffer, std::size_t size);
    bool write_memory(void* address, void* buffer, std::size_t size);
    bool virtual_protect(void** base_address, std::size_t* region_size,
        std::uint32_t new_protection, std::uint32_t* old_protection);
    bool create_remote_thread(void* start_address);

    bool is_attached() const { return attached_; }

private:
    bool syscall(std::uint32_t ioctl_code, void* in_buffer,
        std::uint32_t in_buffer_size, void* out_buffer,
        std::uint32_t out_buffer_size);

    static constexpr const wchar_t* device_name_ = L"\\\\.\\ripEAC";
    bool attached_ = false;
    std::uint32_t process_pid_ = 0;
    HANDLE device_handle_ = nullptr;
};