#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {

    #ifdef _M_IX86
    /**
     * @class Wow64Anycall
     * @brief Executes arbitrary 64-bit shellcode from within a 32-bit process.
     */
    class Wow64Anycall : public Wow64Invoker {
        private:
        std::string _opcode;

        public:
        Wow64Anycall(_In_ std::string  opcode) : _opcode(std::move(opcode)) {}

        /**
         * @brief Triggers the execution of the 64-bit opcodes.
         * @return The 64-bit return value (from the 64-bit RAX register).
         */
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