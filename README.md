<div align="center">
<h1>NtExt</h1>

[English](README.md) | [简体中文](README_CN.md)

[![Language](https://img.shields.io/badge/Language-C++17-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B17)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20WoW64-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-orange.svg)]()
[![Architecture](https://img.shields.io/badge/Arch-Zero%20Inline%20Assembly-critical.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

</div>

<an id="english"></an>
NtExt is an advanced C++ framework for **WoW64 Heaven’s Gate + Indirect Syscall** , Heaven's Gate, and EDR evasion. and load 64-bit kernel32 and bypass user-land hooks.

If you are frustrated with the instability of traditional Heaven's Gate implementations, require direct 64-bit API access from a 32-bit process, or need to bypass deep user-land hooks, NtExt is the definitive solution.

### Highlights

* **Limbo's Gate (WoW64 Heaven’s Gate + Indirect Syscall)**\
  I refer to this specific technique as **"Limbo's Gate"**. It allows a 32-bit process to dynamically resolve System Service Numbers (SSN) and execute raw 64-bit `syscall` instructions indirectly, entirely bypassing `ntdll.dll` Ring 3 hooks in both the 32-bit and 64-bit address spaces.
* **WoW64 64-bit Kernel32 Loading**\
  Loading the 64-bit `kernel32.dll` within a WoW64 process typically fails due to PEB subsystem validation in `LdrLoadDll`. NtExt utilizes a precise PEB spoofing technique (hot-swapping `IMAGE_SUBSYSTEM_WINDOWS_CUI` to `GUI`) to deceive the OS loader, enabling flawless 64-bit module initialization.
* **The Holy Trinity of Gates**
  * **Heaven's Gate**: Seamless segment switching (`0x23` <-> `0x33`) for cross-architecture execution.
  * **Hell's Gate**: Dynamic SSN extraction directly from the in-memory 64-bit export table, eliminating hardcoded OS-specific numbers.
  * **Halo's Gate**: Defeats inline hooks by implementing a neighborhood search algorithm (`_seachImpl`) to deduce the correct SSN from adjacent unhooked functions.
* **Zero-Inline-Assembly Architecture**\
  Powered by a JIT-style dynamic bytecode injection mechanism rather than compiler-specific assembly syntax. It achieves ultimate cross-compiler compatibility (MSVC / GCC / Clang) while maintaining zero-overhead execution in memory.
* **Seamless Cross-Architecture Compilation**\
  Built upon a highly encapsulated low-level architecture, NtExt completely abstracts away the intricate differences between 32-bit and 64-bit environments. Developers can switch target architectures (x86 / x64) during compilation with zero to minimal code modifications.

### Main Functions

NtExt seamlessly supports both WoW64 (32-bit) and Native x64 (64-bit) environments. The framework exposes distinct APIs optimized for each context.

#### Shared 64-bit API

| Function                     | Return Type         | Description                                                                 |
|:-----------------------------|:--------------------|:----------------------------------------------------------------------------|
| `GetTeb64` / `GetPeb64`      | `DWORD64`           | Get the 64-bit TEB/PEB address                                              |
| `GetNtdll64` / `GetKernel64` | `NtResult<DWORD64>` | Get the 64-bit ntdll/kernel32 module base                                   |
| `GetModuleLdrEntry64`        | `NtResult<DWORD64>` | Get the 64-bit `LDR_DATA_TABLE_ENTRY` address for a loaded module           |
| `GetModuleBase64`            | `NtResult<DWORD64>` | Get the 64-bit base address of a loaded module                              |
| `GetProcAddress64`           | `NtResult<DWORD64>` | Resolve and cache a 64-bit exported function address                        |
| `GetSyscallNumber64`         | `NtResult<DWORD64>` | Resolve the packed 64-bit syscall context (SSN + syscall instruction)       |
| `LoadLibrary64`              | `NtResult<DWORD64>` | Load a module into the 64-bit address space through `LdrLoadDll`            |
| `MapKnownDllSection64`       | `NtStatus`          | Map a 64-bit KnownDll section and return the mapped base through an out arg |
| `UnmapKnownDllSection64`     | `NtStatus`          | Unmap a 64-bit KnownDll section view                                        |

#### WoW64-only 32-bit API

| Function                      | Return Type       | Description                                                       |
|:------------------------------|:------------------|:------------------------------------------------------------------|
| `GetTeb32` / `GetPeb32`       | `DWORD`           | Get the 32-bit TEB/PEB address                                    |
| `GetNtdll32` / `GetKernel32`  | `NtResult<DWORD>` | Get the 32-bit ntdll/kernel32 module base                         |
| `GetModuleLdrEntry32`         | `NtResult<DWORD>` | Get the 32-bit `LDR_DATA_TABLE_ENTRY` address for a loaded module |
| `GetModuleBase32`             | `NtResult<DWORD>` | Get the 32-bit base address of a loaded module                    |
| `GetProcAddress32`            | `NtResult<DWORD>` | Resolve and cache a 32-bit exported function address              |
| `GetLdrGetProcedureAddress32` | `NtResult<DWORD>` | Resolve 32-bit `LdrGetProcedureAddress`                           |
| `LoadLibrary32`               | `NtResult<DWORD>` | Load a module into the 32-bit address space                       |
| `MapKnownDllSection32`        | `NtStatus`        | Map a 32-bit KnownDll section through out parameters              |
| `UnmapKnownDllSection32`      | `NtStatus`        | Unmap a 32-bit KnownDll section view                              |
| `memcpy64`                    | `void`            | Copy memory between the 32-bit process and the 64-bit address map |

#### Invocation Helpers

| Helper    | Description                                                                                                               |
|:----------|:--------------------------------------------------------------------------------------------------------------------------|
| `Call`    | Call a 64-bit function from WoW64 or native x64 resolver code                                                             |
| `Syscall` | Execute a direct/indirect syscall from a resolved packed syscall context                                                  |
| `Anycall` | Execute generated machine code with stack alignment and non-volatile register restoration handled by the invoker pipeline |

### Usage

```cpp
#include <NtExt.hpp>
#include <iostream>

using namespace NtExt;

int main() {
    DWORD64 teb64 = Resolver.GetTeb64();
    std::cout << "TEB64: 0x" << std::hex << teb64 << std::endl;

    DWORD64 peb64 = Resolver.GetPeb64();
    std::cout << "PEB64: 0x" << std::hex << peb64 << std::endl;

    auto ntdll64 = Resolver.GetNtdll64();
    if ( !ntdll64 ) {
        std::cout << "GetNtdll64 failed: 0x" << std::hex << ntdll64.Code() << std::endl;
        return 1;
    }
    //normal call Nt function
    auto rtlGetVersion = Resolver.GetProcAddress64(ntdll64.Value(), "RtlGetVersion");
    if ( !rtlGetVersion ) {
        std::cout << "GetProcAddress64 failed: 0x" << std::hex << rtlGetVersion.Code() << std::endl;
        return 1;
    }
    alignas(8) BYTE osvi[ 300 ] = { 0 };
    *(DWORD*) osvi = 284;
    (void) Call(rtlGetVersion.Value())((DWORD64) &osvi);
    DWORD major = *(DWORD*) (osvi + 4);
    DWORD minor = *(DWORD*) (osvi + 8);
    DWORD build = *(DWORD*) (osvi + 12);
    std::cout << "OS Version: " << major << "." << minor << "." << build << std::endl;

    //direct syscall Nt function
    auto syscall = Resolver.GetSyscallNumber64(ntdll64.Value(), "NtReadVirtualMemory");
    if ( !syscall ) {
        std::cout << "GetSyscallNumber64 failed: 0x" << std::hex << syscall.Code() << std::endl;
        return 1;
    }
    WORD dosMagic = 0;
    (void) Syscall(syscall.Value())(
        (DWORD64) -1,
        ntdll64.Value(),
        (DWORD64) &dosMagic,
        (DWORD64) sizeof(dosMagic),
        (DWORD64) 0
        );
    std::cout << "NTDLL DOS Magic: 0x" << std::hex << dosMagic << std::endl;
    system("pause");
    return 0;
}
```
