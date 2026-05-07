#pragma once
#include "Wow64Invoker.hpp"

namespace NtExt {
	#ifdef _M_IX86
	/**
	 * @class Wow64Syscall
	 * @brief Executes a 64-bit System Call (syscall) directly from a 32-bit process.
	 * @details Bypasses WoW64 redirection layers and user-mode hooks by executing a raw x64 syscall instruction.
	 */
	class Wow64Syscall : public Wow64Invoker {
		private:
		DWORD64 _sysCallContext;
		DWORD64 _args[ 16 ] = { 0 };
		DWORD64 _argCount = 0;

		public:
		Wow64Syscall(_In_ DWORD64 sysCallContext) : _sysCallContext(sysCallContext) {
		}

		/**
		 * @brief Triggers the 64-bit syscall with variable arguments.
		 * @tparam Args Variadic template arguments.
		 * @param args The arguments for the syscall.
		 * @return The 64-bit return value from the kernel.
		 */
		template<typename... Args>
		_Check_return_ 
			NtStatus operator()(Args... args) {
			static_assert(sizeof...(args) <= 16, "Wow64Syscall supports up to 16 arguments.");
			memset(_args, 0, sizeof(_args));
			_argCount = sizeof...(args);
			if constexpr ( sizeof...(args) > 0 ) {
				DWORD i = 0;
				((_args[ i++ ] = (DWORD64) args), ...);
			}
			auto invoke = Invoke();
			if ( !invoke ) {
				return NtStatus::Failure(invoke);
			}
			return NtStatus((NTSTATUS) invoke.Value());
		}

		protected:
		VOID onPrepareEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) {
				return;
			}

			if ( _argCount > 0 ) {
				AppendMovImm64(pShell, 0x48, 0xB9, _args[ 0 ]);
			}
			if ( _argCount > 1 ) {
				AppendMovImm64(pShell, 0x48, 0xBA, _args[ 1 ]);
			}
			if ( _argCount > 2 ) {
				AppendMovImm64(pShell, 0x49, 0xB8, _args[ 2 ]);
			}
			if ( _argCount > 3 ) {
				AppendMovImm64(pShell, 0x49, 0xB9, _args[ 3 ]);
			}

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
			if ( !pShell ) {
				return;
			}
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
