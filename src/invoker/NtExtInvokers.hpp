#pragma once

#ifdef _WIN64
#include "./x64/X64Call.hpp"
#include "./x64/X64Syscall.hpp"
#include "./x64/X64Anycall.hpp"
#endif 

#ifdef _M_IX86
#include "./wow64/Wow64Call.hpp"
#include "./wow64/Wow64Syscall.hpp"
#include "./wow64/Wow64Anycall.hpp"
#endif


namespace NtExt {
    #ifdef _WIN64
    _Check_return_ inline X64Call Call(_In_ DWORD64 target) { return X64Call(target); }
    _Check_return_ inline X64Syscall Syscall(_In_ WORD ssn) { return X64Syscall(ssn); }
    _Check_return_ inline X64Anycall Anycall(_In_ const std::string& opcode) { return X64Anycall(opcode); }
    #endif

    #ifdef _M_IX86
    _Check_return_ inline Wow64Call Call(_In_ DWORD64 target) { return Wow64Call(target); }
    _Check_return_ inline Wow64Syscall Syscall(_In_ WORD ssn) { return Wow64Syscall(ssn); }
    _Check_return_ inline Wow64Anycall Anycall(_In_ const std::string& opcode) { return Wow64Anycall(opcode); }
    #endif
}