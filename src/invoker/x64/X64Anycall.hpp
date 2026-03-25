#pragma once 
#include "X64Invoker.hpp"

namespace NtExt {

    #ifdef _WIN64
    /**
     * @class X64Anycall
     * @brief Executes arbitrary, user-provided shellcode or assembly opcodes.
     * @details Directly injects the provided opcode string into the execution buffer.
     */
    class X64Anycall : public X64Invoker {
        private:
        std::string _opcode;

        public:
        X64Anycall(_In_ const std::string& opcode) : _opcode(opcode) {}
        ~X64Anycall() = default;

        /**
         * @brief Triggers the execution of the injected opcodes.
         * @return The 64-bit value present in the RAX register after the opcodes finish executing.
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