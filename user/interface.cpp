#include "interface.h"
#include <stdexcept>


bool Interface::attach(const std::wstring& process_name)
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe32{ sizeof(pe32) };
    if (Process32FirstW(snapshot, &pe32))
    {
        do
        {
            if (wcscmp(pe32.szExeFile, process_name.c_str()) == 0)
            {
                process_pid_ = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);

    if (!process_pid_)
        return false;

    device_handle_ = CreateFileW(device_name_,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (device_handle_ == INVALID_HANDLE_VALUE)
    {
        process_pid_ = 0;
        return false;
    }

    attached_ = true;
    return true;
}
bool Interface::detach()
{
    if (!attached_ || !device_handle_)
        return false;

    CloseHandle(device_handle_);
    device_handle_ = nullptr;
    process_pid_ = 0;
    attached_ = false;
    return true;
}

bool Interface::syscall(std::uint32_t ioctl_code, void* in_buffer,
    std::uint32_t in_buffer_size, void* out_buffer,
    std::uint32_t out_buffer_size)
{
    DWORD bytes_returned = 0;
    return DeviceIoControl(device_handle_,
        ioctl_code,
        in_buffer,
        in_buffer_size,
        out_buffer,
        out_buffer_size,
        &bytes_returned,
        nullptr) != FALSE;
}

bool Interface::virtual_alloc(void** base_address, std::size_t* region_size,
    std::uint32_t allocation_type, std::uint32_t protection_type)
{
    struct virtual_alloc_t
    {
        std::uint32_t process_id;
        void** base_address;
        size_t* region_size;
        std::uint32_t allocation_type;
        std::uint32_t protection_type;
    };

    virtual_alloc_t params{ process_pid_, base_address, region_size,
                          allocation_type, protection_type };

    static constexpr std::uint32_t IOCTL_ALLOCATE_MEMORY = IOCTL_CODE(1);
    return syscall(IOCTL_ALLOCATE_MEMORY, &params, sizeof(params),
        &params, sizeof(params));
}

bool Interface::virtual_free(void** base_address, std::size_t* region_size,
    std::uint32_t free_type)
{
    struct virtual_free_t
    {
        std::uint32_t process_id;
        void** base_address;
        size_t* region_size;
        std::uint32_t free_type;
    };

    virtual_free_t params{ process_pid_, base_address, region_size, free_type };
    static constexpr std::uint32_t IOCTL_FREE_MEMORY = IOCTL_CODE(2);
    return syscall(IOCTL_FREE_MEMORY, &params, sizeof(params),
        &params, sizeof(params));
}

bool Interface::read_memory(void* address, void* buffer, std::size_t size)
{
    struct read_write_t
    {
        enum class flag_t { read, write };

        std::uint32_t process_id;
        void* address;
        void* buffer;
        size_t size;
        flag_t flag;
    };

    read_write_t params{ process_pid_, address, buffer, size,
                       read_write_t::flag_t::read };

    static constexpr std::uint32_t IOCTL_READ_WRITE_MEMORY = IOCTL_CODE(3);
    return syscall(IOCTL_READ_WRITE_MEMORY, &params, sizeof(params),
        &params, sizeof(params));
}

bool Interface::write_memory(void* address, void* buffer, std::size_t size)
{
    struct read_write_t
    {
        enum class flag_t { read, write };

        std::uint32_t process_id;
        void* address;
        void* buffer;
        size_t size;
        flag_t flag;
    };

    read_write_t params{ process_pid_, address, buffer, size,
                       read_write_t::flag_t::write };

    static constexpr std::uint32_t IOCTL_READ_WRITE_MEMORY = IOCTL_CODE(3);
    return syscall(IOCTL_READ_WRITE_MEMORY, &params, sizeof(params),
        &params, sizeof(params));
}

bool Interface::virtual_protect(void** base_address, std::size_t* region_size,
    std::uint32_t new_protection, std::uint32_t* old_protection)
{
    struct virtual_protect_t
    {
        std::uint32_t process_id;
        void** base_address;
        size_t* region_size;
        std::uint32_t new_protection;
        std::uint32_t* old_protection;
    };

    virtual_protect_t params{ process_pid_, base_address, region_size,
                            new_protection, old_protection };

    static constexpr std::uint32_t IOCTL_PROTECT_MEMORY = IOCTL_CODE(4);
    return syscall(IOCTL_PROTECT_MEMORY, &params, sizeof(params),
        &params, sizeof(params));
}

bool Interface::create_remote_thread(void* start_address)
{
    struct thread_hijack_t
    {
        std::uint32_t process_id;
        std::uint32_t thread_id;
        void* start_address;
    };

    thread_hijack_t params{ process_pid_, 0, start_address };

    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 te32{ sizeof(te32) };
    if (Thread32First(snapshot, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == process_pid_)
            {
                params.thread_id = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(snapshot, &te32));
    }

    CloseHandle(snapshot);

    static constexpr std::uint32_t IOCTL_HIJACK_THREAD = IOCTL_CODE(5);
    return syscall(IOCTL_HIJACK_THREAD, &params, sizeof(params),
        &params, sizeof(params));
}