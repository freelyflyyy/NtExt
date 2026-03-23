#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
    #ifdef _WIN64
    class X64Syscall : public X64Invoker {
        private:
        WORD _ssn;
        DWORD64 _args[ 16 ] = { 0 };

        public:
        X64Syscall(_In_ WORD ssn) : _ssn(ssn) {}

        template<typename... Args>
        _Check_return_ _Success_(return != 0)
            DWORD64 operator()(Args... args) {
            memset(_args, 0, sizeof(_args));
            if constexpr ( sizeof...(args) > 0 ) {
                DWORD i = 0;
                ((_args[ i++ ] = (DWORD64) args), ...);
            }
            return Invoke();
        }

        protected:
        virtual VOID onPrepareEnv(_Inout_ std::string* pShell) override {
            InjectPrepareEnv(pShell, _args);
        }

        virtual VOID onEmitOpcode(_Inout_ std::string* pShell) override {
            BYTE syscall_stub[] = {
                0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00, 0x41, 0x53, 0x49, 0x89, 0xCA,
                0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x83, 0xC4, 0x08
            };
            *(DWORD*) (syscall_stub + 13) = (DWORD) _ssn;
            pShell->append((char*) syscall_stub, sizeof(syscall_stub));
        }
    };
    #endif
}