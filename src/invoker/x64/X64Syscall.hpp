#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
    #ifdef _WIN64
    /**
     * @class X64Syscall
     * @brief Executes a direct System Call (syscall) into the Windows kernel, bypassing user-mode API hooks.
     * @details Assembles a custom syscall stub using a provided System Service Number (SSN) and a valid syscall instruction address.
     */
    class X64Syscall : public X64Invoker {
        private:
        DWORD64 _sysCallContext;
        DWORD64 _args[ 16 ] = { 0 };

        public:
        X64Syscall(_In_ DWORD64 sysCallContext) : _sysCallContext(sysCallContext) {}

        /**
         * @brief Overloaded call operator to trigger the kernel syscall with variable arguments.
         * @tparam Args Variadic template arguments representing the parameters for the syscall.
         * @param args The arguments to be passed into the kernel.
         * @return The 64-bit NTSTATUS code or return value from the kernel.
         */
        template<typename... Args>
        _Check_return_
            DWORD64 operator()(Args... args) {
            memset(_args, 0, sizeof(_args));
            if constexpr ( sizeof...(args) > 0 ) {
                DWORD i = 0;
                ((_args[ i++ ] = (DWORD64) args), ...);
            }
            return Invoke();
        }

        protected:
        VOID onPrepareEnv(_Inout_ std::string* pShell) override {
            InjectPrepareEnv(pShell, _args);
        }

        VOID onEmitOpcode(_Inout_ std::string* pShell) override {
            BYTE syscall_stub[] = {
                0x49, 0x89, 0xCA,                                           //  mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,                               //  mov eax, SSN 
                0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  mov r11, Address
                0x41, 0xFF, 0xD3                                            //  call r11
            };
            *(DWORD*) (syscall_stub + 4) = (DWORD) (this->_sysCallContext >> 48);
            *(DWORD64*) (syscall_stub + 10) = this->_sysCallContext & 0x0000FFFFFFFFFFFFULL;
            pShell->append((char*) syscall_stub, sizeof(syscall_stub));
        }
    };
    #endif // _WIN64
}