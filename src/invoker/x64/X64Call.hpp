#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
    #ifdef _WIN64
    class X64Call : public X64Invoker {
        public:
        X64Call(_In_ DWORD64 funcAddr) : X64Invoker(funcAddr) {}
        protected:
        void EmitOpcode(_Inout_ std::string* pShellcode) override {
            BYTE call_stub[] = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xD0
            };
            *(DWORD64*) (call_stub + 2) = _global_target;
            pShellcode->append((char*) call_stub, sizeof(call_stub));
        }
    };
    #endif
}