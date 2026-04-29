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
    /**
     * @brief Creates a native x64 function invoker bound to the supplied target address.
     * @param[in] target The absolute target function address.
     * @return A configured `X64Call` invoker.
     */
    _Check_return_ inline X64Call Call(_In_ DWORD64 target) { return X64Call(target); }

    /**
     * @brief Creates a native x64 syscall invoker bound to the supplied syscall context.
     * @param[in] ssn High 16 bits store the SSN and low 48 bits store the syscall stub address.
     * @return A configured `X64Syscall` invoker.
     */
    _Check_return_ inline X64Syscall Syscall(_In_ DWORD64 ssn) { return X64Syscall(ssn); }

    /**
     * @brief Creates a native x64 arbitrary-opcode invoker.
     * @param[in] opcode Raw machine-code bytes appended to the generated routine.
     * @return A configured `X64Anycall` invoker.
     */
    _Check_return_ inline X64Anycall Anycall(_In_ const std::string& opcode) { return X64Anycall(opcode); }
    #endif

    #ifdef _M_IX86
    /**
     * @brief Creates a WoW64 function invoker bound to the supplied 64-bit target address.
     * @param[in] target The absolute 64-bit target function address.
     * @return A configured `Wow64Call` invoker.
     */
    _Check_return_ inline Wow64Call Call(_In_ DWORD64 target) { return {target}; }

    /**
     * @brief Creates a WoW64 syscall invoker bound to the supplied syscall context.
     * @param[in] ssn High 16 bits store the SSN and low 48 bits store the syscall stub address.
     * @return A configured `Wow64Syscall` invoker.
     */
    _Check_return_ inline Wow64Syscall Syscall(_In_ DWORD64 ssn) { return {ssn}; }

    /**
     * @brief Creates a WoW64 arbitrary-opcode invoker.
     * @param[in] opcode Raw machine-code bytes appended to the generated routine.
     * @return A configured `Wow64Anycall` invoker.
     */
    _Check_return_ inline Wow64Anycall Anycall(_In_ const std::string& opcode) { return {opcode}; }
    #endif
}
