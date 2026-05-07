<div align="center">
  
<h1>NtExt</h1>

[English](README.md) | [简体中文](README_CN.md)

[![Language](https://img.shields.io/badge/Language-C++17-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B17)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20WoW64-lightgrey.svg)]()
[![Build](https://img.shields.io/badge/Build-CMake-orange.svg)]()
[![Architecture](https://img.shields.io/badge/Arch-Zero%20Inline%20Assembly-critical.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

</div>

NtExt 是一个用于WoW64间接X64系统调用、X64地狱之门（Hell's Gate）和EDR规避的高级C++框架。可无缝加载64位kernel32并绕过用户空间挂钩。

如果你厌倦了传统的 Heaven's Gate 、如果你的 32 位程序急需直接调用 64 位的底层 API、或者你在寻找一个能对抗顶级用户态 Hook 的解决方案，NtExt 将是你的最终选择。

## 核心特性

* **Limbo's Gate (WoW64 Heaven’s Gate + Direct Syscall)**\
  我将这项技术命名为 **Limbo's Gate** 。它允许你在 32 位程序中动态解析系统调用号 (SSN) 并直接触发原生 64 位 `syscall` 指令，彻底绕过 32 位与 64 位 `ntdll.dll` 层面所有的 Ring 3 监控。
* **WoW64 加载 64位 Kernel32.dll 难题**\
  在 WoW64 进程中强行加载 64 位 `kernel32.dll` 通常会因 `LdrLoadDll` 的 PEB 子系统验证而失败。NtExt 采用精确的 PEB 伪装技术（热切换 `IMAGE_SUBSYSTEM_WINDOWS_CUI` 到 `GUI`），完美欺骗系统加载器，实现 64 位模块的无损加载。
* **集齐三大底层免杀技术**
  * **Heaven's Gate**: 极简的段寄存器切换 (`0x23` <-> `0x33`)，实现平滑的跨架构代码执行。
  * **Hell's Gate**: 直接从内存中的 64 位导出表提取原生机器码以获取 SSN，告别脆弱的硬编码。
  * **Halo's Gate**: 完美对抗 Inline Hook。当目标函数被篡改时，利用相邻内存搜索算法 (`_seachImpl`) 精准推导出被隐藏的真实 SSN。
* **零内联汇编架构**\
  由类似 JIT 的动态字节码注入机制驱动，而非依赖特定编译器的汇编语法。在保持内存中零开销执行的同时，实现了极致的跨编译器兼容性（MSVC / GCC / Clang）。
* **架构无缝切换**\
  基于对底层架构的极度封装，NtExt 完美抹平了 32 位与 64 位执行环境之间的错综差异。开发者在切换编译目标架构 (x86 / x64) 时，无需修改任何核心代码（或仅需极少量微调）。

## 主要功能
NtExt无缝支持WoW64（32位）和Native x64（64位）环境。

### 通用 64 位 API

| 函数                         | 返回类型            | 说明                                                         |
|:-----------------------------|:--------------------|:-------------------------------------------------------------|
| `GetTeb64` / `GetPeb64`      | `DWORD64`           | 获取 64 位 TEB/PEB 地址                                      |
| `GetNtdll64` / `GetKernel64` | `NtResult<DWORD64>` | 获取 64 位 ntdll/kernel32 模块基址                           |
| `GetModuleLdrEntry64`        | `NtResult<DWORD64>` | 获取 64 位模块的 `LDR_DATA_TABLE_ENTRY` 地址                 |
| `GetModuleBase64`            | `NtResult<DWORD64>` | 获取 64 位模块基址                                           |
| `GetProcAddress64`           | `NtResult<DWORD64>` | 解析并缓存 64 位导出函数地址                                 |
| `GetSyscallNumber64`         | `NtResult<DWORD64>` | 解析打包后的 64 位系统调用上下文，即 SSN 和 syscall 指令地址 |
| `LoadLibrary64`              | `NtResult<DWORD64>` | 通过 `LdrLoadDll` 加载 64 位模块                             |
| `MapKnownDllSection64`       | `NtStatus`          | 映射 64 位 KnownDll section，并通过出参返回映射基址          |
| `UnmapKnownDllSection64`     | `NtStatus`          | 解除映射 64 位 KnownDll section                              |

### WoW64 专属 32 位 API

| 函数                          | 返回类型          | 说明                                           |
|:------------------------------|:------------------|:-----------------------------------------------|
| `GetTeb32` / `GetPeb32`       | `DWORD`           | 获取 32 位 TEB/PEB 地址                        |
| `GetNtdll32` / `GetKernel32`  | `NtResult<DWORD>` | 获取 32 位 ntdll/kernel32 模块基址             |
| `GetModuleLdrEntry32`         | `NtResult<DWORD>` | 获取 32 位模块的 `LDR_DATA_TABLE_ENTRY` 地址   |
| `GetModuleBase32`             | `NtResult<DWORD>` | 获取 32 位模块基址                             |
| `GetProcAddress32`            | `NtResult<DWORD>` | 解析并缓存 32 位导出函数地址                   |
| `GetLdrGetProcedureAddress32` | `NtResult<DWORD>` | 解析 32 位 `LdrGetProcedureAddress` 地址       |
| `LoadLibrary32`               | `NtResult<DWORD>` | 加载 32 位模块                                 |
| `MapKnownDllSection32`        | `NtStatus`        | 映射 32 位 KnownDll section，并通过出参返回值  |
| `UnmapKnownDllSection32`      | `NtStatus`        | 解除映射 32 位 KnownDll section                |
| `memcpy64`                    | `void`            | 在 32 位进程和 64 位地址空间之间拷贝内存       |

### 调用辅助

| 辅助接口  | 说明                                                   |
|:----------|:-------------------------------------------------------|
| `Call`    | 调用解析到的 64 位函数                                 |
| `Syscall` | 通过解析到的系统调用上下文执行直接或间接系统调用       |
| `Anycall` | 执行动态生成的机器码，并处理栈对齐和非易失寄存器恢复   |

## 使用示例

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
