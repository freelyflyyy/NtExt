#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {
	#ifdef _M_IX86
	class Wow64Syscall : public Wow64Invoker {
		private:
		DWORD64 _sysCallContext;
		DWORD64 _args[ 16 ] = { 0 };
		DWORD64 _argCount = 0;

		public:
		/**
		 * @brief Binds a pre-resolved syscall context for later invocation from WoW64.
		 * @param[in] sysCallContext High 16 bits store the SSN and low 48 bits store the syscall stub address.
		 */
		Wow64Syscall(_In_ DWORD64 sysCallContext) : _sysCallContext(sysCallContext) {
		}

		template<typename... Args>
		_Check_return_ 
			DWORD64 operator()(Args... args) {
			static_assert(sizeof...(args) <= 16, "Wow64Syscall supports up to 16 arguments.");
			memset(_args, 0, sizeof(_args));
			_argCount = sizeof...(args);
			if constexpr ( sizeof...(args) > 0 ) {
				DWORD i = 0;
				((_args[ i++ ] = (DWORD64) args), ...);
			}
			return Invoke();
		}

		protected:
		/**
		 * @brief Encodes syscall arguments according to the x64 Windows calling convention.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
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

		/**
		 * @brief Emits the raw syscall trampoline using the stored syscall context.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		VOID onEmitOpcode(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;
			BYTE syscall_stub[] = {
				0x49, 0x89, 0xCA,
				0xB8, 0x00, 0x00, 0x00, 0x00,
				0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x41, 0xFF, 0xD3,
			};
			*(DWORD*) (syscall_stub + 4) = (DWORD) (this->_sysCallContext >> 48);
			*(DWORD64*) (syscall_stub + 10) = this->_sysCallContext & 0x0000FFFFFFFFFFFFULL;

			pShell->append((char*) syscall_stub, sizeof(syscall_stub));
		}
	};
	#endif // _M_IX86
}
