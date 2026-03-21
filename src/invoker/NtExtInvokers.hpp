#pragma once

#ifdef _WIN64
#include "./x64/X64Call.hpp"
#include "./x64/X64Syscall.hpp"
#endif 

#ifdef _M_IX86
#include "./wow64/Wow64Call.hpp"
#include "./wow64/Wow64Syscall.hpp"
#endif


namespace NtExt {
    #ifdef _WIN64
    inline X64Call Call(DWORD64 target) { return X64Call(target); }
    inline X64Syscall Syscall(WORD ssn) { return X64Syscall(ssn); }
    #endif

    #ifdef _M_IX86
    inline Wow64Call Call(DWORD64 target) { return Wow64Call(target); }
    inline Wow64Syscall Syscall(WORD ssn) { return Wow64Syscall(ssn); }
    #endif
}