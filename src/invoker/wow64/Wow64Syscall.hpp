#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {

	#ifdef _M_IX86
	class Wow64Syscall : public Wow64Invoker{
		public:
		Wow64Syscall(_In_ DWORD64 ssn) : Wow64Invoker(ssn) {}

		protected:
        VOID EmitOpcode(_Inout_ std::string* pShell) override {
            BYTE syscall_stub[] = {
                0x4C, 0x8D, 0x1D, 0x0C, 0x00, 0x00, 0x00,
                0x41, 0x53,
                0x49, 0x89, 0xCA,
                0xB8, 0x00, 0x00, 0x00, 0x00,
                0x0F, 0x05,
                0x48, 0x83, 0xC4, 0x08
            };
            *(DWORD*) (syscall_stub + 13) = (DWORD) _global_target;
            pShell->append((char*) syscall_stub, sizeof(syscall_stub));
        }
	};
	#endif // _M_IX86
}