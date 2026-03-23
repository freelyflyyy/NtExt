#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {

    #ifdef _M_IX86
    class Wow64Anycall : public Wow64Invoker {
        private:
        std::string _opcode;

        public:
        Wow64Anycall(_In_ const std::string& opcode) : _opcode(opcode) {}

        _Check_return_ _Success_(return != 0)
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