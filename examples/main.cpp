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
