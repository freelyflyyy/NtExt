#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
    #ifdef _WIN64
    class X64Syscall : public X64Invoker {
        public:
        X64Syscall(_In_ WORD ssn) : X64Invoker((DWORD64) ssn) {}
        protected:
        void EmitOpcode(_Inout_ std::string* pShellcode) override {
            BYTE syscall_stub[] = {
                0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00,
                0x41, 0x53,
                0x49, 0x89, 0xCA,
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x05,
                0x48, 0x83, 0xC4, 0x08
            };
            *(DWORD*) (syscall_stub + 13) = (DWORD) _global_target;
            pShellcode->append((char*) syscall_stub, sizeof(syscall_stub));
        }
    };
    #endif
}