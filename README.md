<div align="center">
<h1>NtExt</h1>

[English](README.md) | [简体中文](README_CN.md)

[![Language](https://img.shields.io/badge/Language-C++17-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B17)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20WoW64-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-orange.svg)]()
[![Architecture](https://img.shields.io/badge/Arch-Zero%20Inline%20Assembly-critical.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

</div>

<a id="english"></a>
NtExt is an advanced C++ framework for **WoW64 Heaven’s Gate + Direct Syscall** , Heaven's Gate, and EDR evasion. and load 64-bit kernel32 and bypass user-land hooks.

If you are frustrated with the instability of traditional Heaven's Gate implementations, require direct 64-bit API access from a 32-bit process, or need to bypass deep user-land hooks, NtExt is the definitive solution.

### Highlights

* **Limbo's Gate (WoW64 Heaven’s Gate + Direct Syscall)**\
  I refer to this specific technique as **"Limbo's Gate"**. It allows a 32-bit process to dynamically resolve System Service Numbers (SSN) and execute raw 64-bit `syscall` instructions directly, entirely bypassing `ntdll.dll` Ring 3 hooks in both the 32-bit and 64-bit address spaces.
* **WoW64 64-bit Kernel32 Loading**\
  Loading the 64-bit `kernel32.dll` within a WoW64 process typically fails due to PEB subsystem validation in `LdrLoadDll`. NtExt utilizes a precise PEB spoofing technique (hot-swapping `IMAGE_SUBSYSTEM_WINDOWS_CUI` to `GUI`) to deceive the OS loader, enabling flawless 64-bit module initialization.
* **The Holy Trinity of Gates**
  * **Heaven's Gate**: Seamless segment switching (`0x23` <-> `0x33`) for cross-architecture execution.
  * **Hell's Gate**: Dynamic SSN extraction directly from the in-memory 64-bit export table, eliminating hardcoded OS-specific numbers.
  * **Halo's Gate**: Defeats inline hooks by implementing a neighbourhood search algorithm (`_seachImpl`) to deduce the correct SSN from adjacent unhooked functions.
* **Zero-Inline-Assembly Architecture**\
  Powered by a JIT-style dynamic bytecode injection mechanism rather than compiler-specific assembly syntax. It achieves ultimate cross-compiler compatibility (MSVC / GCC / Clang) while maintaining zero-overhead execution in memory.

### Main Functions API Reference

NtExt seamlessly supports both WoW64 (32-bit) and Native x64 (64-bit) environments. The framework exposes distinct APIs optimized for each context.

#### 1. WoW64 Context (32-bit to 64-bit Execution)
*These functions are specifically designed to bridge the 32-bit process with the 64-bit subsystem.*

| Function | Attribute | Description |
| :--- | :---: | :--- |
| `GetTeb64` / `GetPeb64` | **[Ex]** | Get the 64-bit TEB/PEB base address across the boundary |
| `GetNtdll64` / `GetKernel64`| **[Ex]** | Get the 64-bit ntdll/kernel32 base address |
| `LoadLibrary64` | **[Ex]** | Load a specified module natively in the 64-bit space |
| `GetModuleBase64` | **[Ex]** | Get the base address of a specified module in 64-bit |
| `GetModuleLdrEntry64` | **[Ex]** | Get the `LDR_DATA_TABLE_ENTRY` structure of a specified module |
| `GetProcAddress64` | **[Ex]** | Get the address of a specified function in 64-bit **(Cached)** |
| `GetSyscallNumber64` | **[Ex]** | Get the SSN of a specified function in 64-bit |
| `GetLdrGetProcedureAddress64`| **[Ex]** | Get the address of the `LdrGetProcedureAddress` function in 64-bit |
| `Call` | **[Ex]** | Cross-architecture call to a specified 64-bit function |
| `Syscall` | **[Ex]** | Cross-architecture direct Syscall to a 64-bit function |
| `memcpy64` | **[Ex] | Safe memory copy bridging 32-bit and 64-bit address spaces |

### Usage

```cpp
#include <iostream>
#include <NtExt.hpp>

using namespace NtExt;

int main() {
    // 1. Normal cross-architecture call
    DWORD64 ntdll64 = Resolver.GetNtdll64();
    DWORD64 pRtlGetVersion = Resolver.GetProcAddress64(ntdll64, "RtlGetVersion");
    
    alignas(8) BYTE osvi[300] = { 0 };
    *(DWORD*)osvi = 284; 
    NTSTATUS status = Call(pRtlGetVersion)((DWORD64)&osvi);
    
    if (status == 0) {
        DWORD major = *(DWORD*)(osvi + 4);
        DWORD minor = *(DWORD*)(osvi + 8);
        DWORD build = *(DWORD*)(osvi + 12);
        std::cout << "[+] OS Version: " << major << "." << minor << "." << build << std::endl;
    }

    // 2. Direct Syscall (Limbo's Gate / Hell's Gate)
    DWORD64 ssn = Resolver.GetSyscallNumber64(ntdll64, "NtReadVirtualMemory");
    WORD dosMagic = 0;
    
    NTSTATUS status2 = Syscall((WORD) ssn)(
        (DWORD64) -1,               
        (DWORD64) ntdll64,          
        (DWORD64) &dosMagic,        
        (DWORD64) sizeof(dosMagic), 
        (DWORD64) 0                 
    );
    
    if (status2 == 0) {
        std::cout << "[+] NTDLL DOS Magic: 0x" << std::hex << dosMagic << std::endl;
    }
    return 0;
}
