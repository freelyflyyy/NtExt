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
			BYTE syscall_stub[] = {
				0x49, 0x89, 0xCA,                                           // mov r10, rcx
				0xB8, 0x00, 0x00, 0x00, 0x00,                               // mov eax, SSN
				0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r11, Address
				0x41, 0xFF, 0xD3,                                           // call r11
			};
			*(DWORD*) (syscall_stub + 4) = (DWORD) (this->_sysCallContext >> 48);
			*(DWORD64*) (syscall_stub + 10) = this->_sysCallContext & 0x0000FFFFFFFFFFFFULL;

			pShell->append((char*) syscall_stub, sizeof(syscall_stub));
		}
	};
	#endif // _M_IX86
}