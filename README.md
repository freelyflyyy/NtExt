# NtCallExt
A hacker tool implemented in C++ for x86/x64 Windows platforms, featuring the heavens gate technology for Wow64

---

## Features
The following are the main functions of NtCallExt  
**Only introduce X86 functions**

### X86
| Function | Attribute | Description |
| :--- | :---: | :--- |
| `GetTeb64` | **[Ex]** | Get the 64-bit TEB base address |
| `GetPeb64` | **[Ex]** | Get the 64-bit PEB base address |
| `GetNtdll64` | **[Ex]** | Get the 64-bit ntdll base address |
| `GetKernel64` | **[Ex]** | Get the 64-bit kernelbase base address |
| `LoadLibrary64` | **[Ex]** | Load a specified module in 64-bit |
| `GetModuleBase64` | **[Ex]** | Get the base address of a specified module in 64-bit |
| `GetModuleLdrEntry64` | **[Ex]** | Get the ***LDR_DATA_TABLE_ENTRY*** structure of a specified module in 64-bit |
| `GetProcAddress64` | **[Ex]** | Get the address of a specified function in 64-bit |
| `GetLdrGetProcedureAddress` | **[Ex]** | Get the address of the ***LdrGetProcedureAddress*** function in 64-bit |
| `X64Call` | **[Ex]** | Call a specified function in 64-bit |
| `memcpy64` | **[Ex]** | Copy memory in 64-bit |
| `GetTeb32` | | Get the 32-bit TEB base address |
| `GetPeb32` | | Get the 32-bit PEB base address |
| `GetNtdll32` | | Get the 32-bit ntdll base address |
| `GetKernel32` | | Get the 32-bit kernel32 base address |
| `LoadLibrary32` | | Load a specified module in 32-bit |
| `GetModuleBase32` | | Get the base address of a specified module in 32-bit |
| `GetProcAddress32` | | Get the address of a specified function in 32-bit |
| `GetLdrGetProcedureAddress32` | | Get the address of the ***LdrGetProcedureAddress*** function in 32-bit |

### Common
The following are common functions
| Function | Description |
| :--- | :--- |
| `IsCached64/32` | Check whether the specified module or function has been cached |
| `GetFunc64/32` | Get the address of a specified function, with caching mechanism |
| `MakeUTF/ANSIStr` | Wide character/single character encoding conversion and packaging |

---

## Usage

```cpp
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