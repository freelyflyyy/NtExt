#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {

	#ifdef _M_IX86
	class Wow64Call : public Wow64Invoker {
		public:
		Wow64Call(_In_ DWORD64 funcAddr) : Wow64Invoker(funcAddr) {}


		protected:
		virtual VOID EmitOpcode(_Inout_ std::string* pShell) override {
			BYTE call_stub[] = {
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xD0
			};
			*(DWORD64*) (call_stub + 2) = _global_target;
			pShell->append((char*) call_stub, sizeof(call_stub));
		}
	};
	#endif // _M_IX86
}