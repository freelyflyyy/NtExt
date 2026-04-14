#pragma once
#include "../pch/stdafx.h"

namespace NtExt {

	namespace Internal {
		static constexpr BYTE backup_env[] = {
			0x55,                                                        // push rbp
			0x48, 0x89, 0xE5,                                            // mov rbp, rsp
			0x53,                                                        // push rbx
			0x56,                                                        // push rsi
			0x57,                                                        // push rdi
		}; 
		
		static constexpr BYTE restore_env[] = {
			0x48, 0x89, 0xC2,                                            // mov rdx, rax
			0x48, 0xC1, 0xEA, 0x20,                                      // shr rdx, 32
			0x48, 0x8D, 0x65, 0xE8,                                      // lea rsp, [rbp - 0x18]
			0x5F,                                                        // pop rdi
			0x5E,                                                        // pop rsi
			0x5B,                                                        // pop rbx
			0x5D,                                                        // pop rbp
			0xC3                                                         // ret
		};
	}

	/**
	 * @class InvokerBase
	 * @brief Common shellcode builder and trampoline executor for all invoker implementations.
	 * @details Derived classes contribute prologue, argument setup, payload emission, and epilogue bytes
	 *          through the virtual hook methods. The assembled routine is then copied into executable memory
	 *          and invoked as a `DWORD64 (*)()` function.
	 */
	class InvokerBase {
		public:
		/**
		 * @brief Releases the invoker instance.
		 */
		virtual ~InvokerBase() = default;

		InvokerBase(const InvokerBase&) = delete;
		InvokerBase& operator=(const InvokerBase&) = delete;

		protected:
		/**
		 * @brief Initializes the base invoker state.
		 */
		InvokerBase() = default;

		std::string _shellcode;

		/**
		 * @brief Emits the routine prologue needed before payload execution.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		virtual VOID onBackupEnv(_Inout_ std::string* pShell) = 0;

		/**
		 * @brief Emits the routine epilogue needed after payload execution.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		virtual VOID onRestoreEnv(_Inout_ std::string* pShell) = 0;

		/**
		 * @brief Emits argument marshaling and calling-convention setup code.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		virtual VOID onPrepareEnv(_Inout_ std::string* pShell) {}

		/**
		 * @brief Emits the payload-specific opcodes.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		virtual VOID onEmitOpcode(_Inout_ std::string* pShell) {}

		/**
		 * @brief Builds the executable shellcode routine for the current invocation.
		 * @param[in,out] pShell Receives the full assembled routine.
		 * @retval TRUE The routine was assembled successfully.
		 * @retval FALSE The output buffer was null or no code was emitted.
		 */
		_Check_return_ _Success_(return != FALSE)
			virtual BOOL CompileRoutine(_Inout_ std::string* pShell) {
			if ( !pShell ) return FALSE;
			pShell->clear();
			onBackupEnv(pShell);
			onPrepareEnv(pShell);
			onEmitOpcode(pShell);
			onRestoreEnv(pShell);
			return !pShell->empty();
		}

		public:
		/**
		 * @brief Allocates executable memory, copies the assembled routine, and runs it.
		 * @return The 64-bit value returned by the generated routine, or `0` on failure.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD64 Invoke() {
			if ( !CompileRoutine(&_shellcode) ) return 0;

			LPVOID pExecuteMemory = VirtualAlloc(NULL, _shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if ( !pExecuteMemory ) return 0;

			memcpy(pExecuteMemory, _shellcode.data(), _shellcode.size());
			DWORD oldProtect;
			VirtualProtect(pExecuteMemory, _shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);

			auto FnExecuteCode = (DWORD64(*)()) pExecuteMemory;
			const DWORD64 result = FnExecuteCode();
			VirtualFree(pExecuteMemory, 0, MEM_RELEASE);
			return result;
		}
	};
}
