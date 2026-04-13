#include <NtExt.hpp>
#include <iomanip>
#include <iostream>

using namespace NtExt;

namespace {

void PrintHex64(const char* label, DWORD64 value) {
    std::cout << label << "0x"
              << std::hex << std::uppercase << value
              << std::dec << std::nouppercase << '\n';
}

void PrintHex32(const char* label, DWORD value) {
    std::cout << label << "0x"
              << std::hex << std::uppercase << value
              << std::dec << std::nouppercase << '\n';
}

void QueryMemoryInfoTest() {
    constexpr DWORD kTargetPid = 33772;
    constexpr DWORD64 kTargetAddress = 0x00007FF78A696000ULL;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, kTargetPid);
    if ( !hProcess ) {
        std::cout << "OpenProcess failed.\n";
        PrintHex32("GetLastError: ", GetLastError());
        return;
    }

    MEMORY_BASIC_INFORMATION64 mbi = { 0 };
    DWORD64 returnLength = 0;

    DWORD64 ntdll64 = Resolver.GetNtdll64();
    DWORD64 packedSyscall = Resolver.GetSyscallNumber64(ntdll64, "NtQueryVirtualMemory");
    if ( !packedSyscall ) {
        std::cout << "GetSyscallNumber64(NtQueryVirtualMemory) failed.\n";
        CloseHandle(hProcess);
        return;
    }

    NTSTATUS status = static_cast<NTSTATUS>(Syscall(packedSyscall)(
        static_cast<DWORD64>(reinterpret_cast<ULONG_PTR>(hProcess)),
        kTargetAddress,
        static_cast<DWORD64>(0),
        static_cast<DWORD64>(reinterpret_cast<ULONG_PTR>(&mbi)),
        static_cast<DWORD64>(sizeof(mbi)),
        static_cast<DWORD64>(reinterpret_cast<ULONG_PTR>(&returnLength))
    ));

    std::cout << "QueryMemoryInfo test\n";
    std::cout << "PID: " << kTargetPid << '\n';
    PrintHex64("Address: ", kTargetAddress);
    PrintHex64("NtQueryVirtualMemory packed syscall: ", packedSyscall);
    PrintHex32("NTSTATUS: ", static_cast<DWORD>(status));
    PrintHex64("ReturnLength: ", returnLength);

    if ( NT_SUCCESS(status) ) {
        PrintHex64("BaseAddress: ", mbi.BaseAddress);
        PrintHex64("AllocationBase: ", mbi.AllocationBase);
        PrintHex32("AllocationProtect: ", mbi.AllocationProtect);
        PrintHex64("RegionSize: ", mbi.RegionSize);
        PrintHex32("State: ", mbi.State);
        PrintHex32("Protect: ", mbi.Protect);
        PrintHex32("Type: ", mbi.Type);
    }

    CloseHandle(hProcess);
}

} // namespace

int main() {
    QueryMemoryInfoTest();
    return 0;
}
