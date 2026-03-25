#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {

    #ifdef _M_IX86
    class Wow64Anycall : public Wow64Invoker {
        private:
        std::string _opcode;

        public:
        Wow64Anycall(_In_ std::string  opcode) : _opcode(std::move(opcode)) {}

        _Check_return_
            DWORD64 operator()() {
            return Invoke();
        }

        protected:
        VOID onEmitOpcode(_Inout_ std::string* pShell) override {
            pShell->append(_opcode);
        }
    };
    #endif
}