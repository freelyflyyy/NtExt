#pragma once 
#include "X64Invoker.hpp"

namespace NtExt {

    #ifdef _WIN64
    class X64Anycall : public X64Invoker {
        private:
        std::string _opcode;

        public:
        X64Anycall(_In_ const std::string& opcode) : _opcode(opcode) {}
        ~X64Anycall() = default;

        _Check_return_
            DWORD64 operator()() {
            return Invoke();
        }

        protected:
        virtual VOID onEmitOpcode(_Inout_ std::string* pShell) override {
            pShell->append(_opcode);
        }
    };
    #endif
}