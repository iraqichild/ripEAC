#ifndef COMMUNCATION_H
#define COMMUNCATION_H

#include "imports.h"

#define IOCTL_BASE 0x8000
#define IOCTL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ALLOCATE_MEMORY IOCTL_CODE(1)
#define IOCTL_FREE_MEMORY IOCTL_CODE(2)
#define IOCTL_READ_WRITE_MEMORY IOCTL_CODE(3)
#define IOCTL_PROTECT_MEMORY IOCTL_CODE(4)
#define IOCTL_HIJACK_THREAD IOCTL_CODE(5)

struct virtual_alloc_t
{
	std::uint32_t process_id;
	void** base_address;
	size_t* region_size;
	std::uint32_t allocation_type;
	std::uint32_t protection_type;
};

struct virtual_free_t
{
	std::uint32_t process_id;
	void** base_address;
	size_t* region_size;
	std::uint32_t free_type;
};

struct read_write_t
{
	enum class flag_t { read, write };

	std::uint32_t process_id;
	void* address;
	void* buffer;
	size_t size;
	flag_t flag;
};

struct virtual_protect_t
{
	std::uint32_t process_id;
	void** base_address;
	size_t* region_size;
	std::uint32_t new_protection;
	std::uint32_t* old_protection;
};

struct thread_hijack_t
{
	std::uint32_t process_id;
	std::uint32_t thread_id;
	void* start_address;
};

#endif