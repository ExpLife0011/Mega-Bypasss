#include <Windows.h>
#include "stdafx.h"

#define READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define SET_ID_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define GAME_MANAGER 0x47F00D0
#define ENTITY_LIST 0xD0

typedef struct _READ_MEM
{
	DWORD64 address;
	DWORD64 response;
	ULONG size;

} READ_MEM, *PREAD_MEM;

typedef struct _WRITE_MEM
{
	DWORD64 address;
	float value;
	ULONG size;

} WRITE_MEM, *PWRITE_MEM;

class Wrappers
{
public:
	HANDLE hDriver;
	// Open a handle to the driver
	Wrappers(LPCSTR RegistryPath)
	{
		hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	// Simple read function
	DWORD64 RPM(DWORD64 address, SIZE_T size)
	{
		READ_MEM read;

		read.address = address;
		read.size = size;

		if (DeviceIoControl(hDriver, READ_REQUEST, &read, sizeof(read), &read, sizeof(read), 0, 0))
			return (DWORD64)read.response;
		else
			return false;
	}

	// Simple write function
	bool WPM(DWORD64 address, float value, SIZE_T size)
	{
		DWORD bytes;
		WRITE_MEM  write;

		write.address = address;
		write.value = value;
		write.size = size;

		if (DeviceIoControl(hDriver, WRITE_REQUEST, &write, sizeof(write), 0, 0, &bytes, NULL))
			return true;
		else
			return false;
	}

	// Sets the games PID in the driver
	DWORD SetTargetPid(DWORD PID)
	{
		DWORD Bytes;

		if (DeviceIoControl(hDriver, SET_ID_REQUEST, &PID, sizeof(PID), 0, 0, &Bytes, NULL))
			return true;
		else
			return false;
	}

	// Get's the main modules base address
	DWORD64 GetMainModule()
	{
		DWORD64 MainModule;

		if (DeviceIoControl(hDriver, GET_MODULE_REQUEST, 0, 0, &MainModule, sizeof(MainModule), 0, 0))
			return MainModule;
		else
			return false;
	}
};