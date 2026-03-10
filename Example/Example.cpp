#include <iostream>
#include "NtCallExt.h"

int main()
{
	DWORD64 func = GET_NTFUNC("NtQuerySystemInformation");
	std::cout << "NtQuerySystemInformation address: 0x" << std::hex << func << std::dec << std::endl;

	DWORD64 kernel32_64 = LOADLIB64(L"kernel32.dll");
	std::cout << "kernel32.dll base address: 0x" << std::hex << kernel32_64 << std::dec << std::endl;

	DWORD64 openProcess_64 = GET_FUNC64(kernel32_64, "OpenProcess");
	std::cout << "OpenProcess address: 0x" << std::hex << openProcess_64 << std::dec << std::endl;

	DWORD64 handle = CALL64_FUNC(openProcess_64, PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	std::cout << "OpenProcess handle: 0x" << std::hex << handle << std::dec << std::endl;
	return 0;
}