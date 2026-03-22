# NtExt

[English](README.md) | [简体中文](README_CN.md)

[![Language](https://img.shields.io/badge/Language-C++17-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B17)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x86%2Fx64-lightgrey.svg)]()\
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

NtExt 是一个用于WoW64直接X64系统调用、天堂之门（Heaven's Gate）和EDR规避的高级C++框架。可无缝加载64位kernel32并绕过用户空间挂钩。

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
* **NVI 架构设计**\
  基于 Non-Virtual Interface 模式构建了极其干净的 `NtExt::Call` 接口，并内置基于读写锁 (Shared Mutex) 的安全缓存系统，最大程度降低内存解析开销。

## 主要功能 (x86 环境)
*以下仅列出 WoW64 环境下的专属功能。纯 64 位环境下的功能与此类似。*

| 函数 | 属性 | 描述 |
| :--- | :---: | :--- |
| `GetTeb64` / `GetPeb64` | **[Ex]** | 获取 64 位 TEB/PEB 基址 |
| `GetNtdll64` / `GetKernel64`| **[Ex]** | 获取 64 位 ntdll/kernel32 模块基址 |
| `LoadLibrary64` | **[Ex]** | 在 64 位空间中加载指定模块 |
| `GetModuleBase64` | **[Ex]** | 获取指定 64 位模块的基址 |
| `GetModuleLdrEntry64` | **[Ex]** | 获取指定 64 位模块的 `LDR_DATA_TABLE_ENTRY` 结构 |
| `GetProcAddress64` | **[Ex]** | 获取指定 64 位函数的物理地址 **(已缓存)** |
| `GetSyscallNumber64` | **[Ex]** | 获取指定 64 位函数的系统调用号 (SSN) |
| `GetLdrGetProcedureAddress64`| **[Ex]** | 获取 64 位 `LdrGetProcedureAddress` 函数地址 |
| `Call` | **[Ex]** | 跨架构调用指定的 64 位函数 |
| `Syscall` | **[Ex]** | 跨架构执行 64 位直接系统调用 |
| `memcpy64` | **[Ex]** | 连接 32 位与 64 位内存空间的安全拷贝函数 |


## 使用方法

```cpp
#include <iostream>
#include <NtExt.hpp>

using namespace NtExt;

int main() {
    // 1. 标准跨架构函数调用
    DWORD64 ntdll64 = Resolver.GetNtdll64();
    DWORD64 pRtlGetVersion = Resolver.GetProcAddress64(ntdll64, "RtlGetVersion");
    
    alignas(8) BYTE osvi[300] = { 0 };
    *(DWORD*)osvi = 284; 
    NTSTATUS status = Call(pRtlGetVersion)((DWORD64)&osvi);
    
    if (status == 0) {
        DWORD major = *(DWORD*)(osvi + 4);
        DWORD minor = *(DWORD*)(osvi + 8);
        DWORD build = *(DWORD*)(osvi + 12);
        std::cout << "[+] 操作系统版本: " << major << "." << minor << "." << build << std::endl;
    }

    // 2. 直接系统调用 (Limbo's Gate)
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
        std::cout << "[+] NTDLL DOS 魔数: 0x" << std::hex << dosMagic << std::endl;
    }
    return 0;
}
