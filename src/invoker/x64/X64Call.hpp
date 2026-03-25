#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Call : public X64Invoker {
		private:
		DWORD64 _funcAddr;
		DWORD64 _args[ 16 ] = { 0 };

		public:
		X64Call(_In_ DWORD64 funcAddr) : _funcAddr(funcAddr) {}

		template<typename... Args>
		_Check_return_ 
			DWORD64 operator()(Args... args) {
			memset(_args, 0, sizeof(_args));
			if constexpr ( sizeof...(args) > 0 ) {
				DWORD i = 0;
				((_args[ i++ ] = (DWORD64) args), ...);
			}
			return Invoke();
		}

		protected:
		VOID onPrepareEnv(_Inout_ std::string* pShell) override {
			InjectPrepareEnv(pShell, _args);
		}

		VOID onEmitOpcode(_Inout_ std::string* pShell) override {
			BYTE call_stub[] = {
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xD0
			};
			*(DWORD64*) (call_stub + 2) = _funcAddr;
			pShell->append((char*) call_stub, sizeof(call_stub));
		}
	};
	#endif
}