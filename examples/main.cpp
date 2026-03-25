#include <NtExt.hpp>
#include <iostream>

using namespace NtExt;

int main() {
    DWORD64 teb64 = Resolver.GetTeb64();
    std::cout << "TEB64: 0x" << std::hex << teb64 << std::endl;

    DWORD64 peb64 = Resolver.GetPeb64();
    std::cout << "PEB64: 0x" << std::hex << peb64 << std::endl;

    DWORD64 ntdll64 = Resolver.GetNtdll64();

    //normal call Nt function
    DWORD64 pRtlGetVersion = Resolver.GetProcAddress64(ntdll64, "RtlGetVersion");
    alignas(8) BYTE osvi[ 300 ] = { 0 };
    *(DWORD*) osvi = 284;
    (void)Call(pRtlGetVersion)((DWORD64) &osvi);
    DWORD major = *(DWORD*) (osvi + 4);
    DWORD minor = *(DWORD*) (osvi + 8);
    DWORD build = *(DWORD*) (osvi + 12);
    std::cout << "OS Version: " << major << "." << minor << "." << build << std::endl;

    //direct syscall Nt function
    DWORD64 syscall = Resolver.GetSyscallNumber64(ntdll64, "NtReadVirtualMemory");
    WORD dosMagic = 0;
    (void)Syscall((DWORD64) syscall)(
        (DWORD64) -1,
        (DWORD64) ntdll64,
        (DWORD64) &dosMagic,
        (DWORD64) sizeof(dosMagic),
        (DWORD64) 0
        );
    std::cout << "NTDLL DOS Magic: 0x" << std::hex << dosMagic << std::endl;
    system("pause");
    return 0;
}