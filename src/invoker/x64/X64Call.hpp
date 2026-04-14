#pragma once
#include "X64Invoker.hpp"

namespace NtExt {
	#ifdef _WIN64
	/**
	 * @class X64Call
	 * @brief Dynamically executes a standard function at a specified 64-bit memory address.
	 * @details Uses the x64 calling convention to pass arguments and jump to the target address.
	 */
	class X64Call : public X64Invoker {
		private:
		DWORD64 _funcAddr;
		DWORD64 _args[ 16 ] = { 0 };
		DWORD64 _argCount = 0;

		public:
		X64Call(_In_ DWORD64 funcAddr) : _funcAddr(funcAddr) {}

		template<typename... Args>
		_Check_return_ 
			DWORD64 operator()(Args... args) {
			static_assert(sizeof...(args) <= 16, "X64Call supports up to 16 arguments.");
			memset(_args, 0, sizeof(_args));
			_argCount = sizeof...(args);
			if constexpr ( sizeof...(args) > 0 ) {
				DWORD i = 0;
				((_args[ i++ ] = (DWORD64) args), ...);
			}
			return Invoke();
		}

		protected:
		VOID onPrepareEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;

			if ( _argCount > 0 ) AppendMovImm64(pShell, 0x48, 0xB9, _args[ 0 ]);
			if ( _argCount > 1 ) AppendMovImm64(pShell, 0x48, 0xBA, _args[ 1 ]);
			if ( _argCount > 2 ) AppendMovImm64(pShell, 0x49, 0xB8, _args[ 2 ]);
			if ( _argCount > 3 ) AppendMovImm64(pShell, 0x49, 0xB9, _args[ 3 ]);

			DWORD64 stackArgCount = (_argCount > 4) ? (_argCount - 4) : 0;
			if ( stackArgCount & 1 ) {
				static constexpr BYTE align_rsp[] = { 0x48, 0x83, 0xEC, 0x08 };
				pShell->append((char*) align_rsp, sizeof(align_rsp));
			}

			for ( LONG64 i = (LONG64) _argCount - 1; i >= 4; --i ) {
				AppendMovImm64(pShell, 0x48, 0xB8, _args[ i ]);
				static constexpr BYTE push_rax[] = { 0x50 };
				pShell->append((char*) push_rax, sizeof(push_rax));
			}

			static constexpr BYTE shadow_space[] = { 0x48, 0x83, 0xEC, 0x20 };
			pShell->append((char*) shadow_space, sizeof(shadow_space));
		}

		VOID onEmitOpcode(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;
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
