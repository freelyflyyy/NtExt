#pragma once
#include "../InvokerBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	/**
	 * @class X64Invoker
	 * @brief Base class for native x64 invokers.
	 * @details This specialization only needs to preserve and restore the native x64 execution environment,
	 *          because no WoW64 mode switch is required.
	 */
	class X64Invoker : public InvokerBase {
		protected:
		/**
		 * @brief Initializes the native x64 invoker base.
		 */
		X64Invoker() : InvokerBase() {}

		/**
		 * @brief Appends a `mov reg, imm64` instruction to the shellcode stream.
		 * @param[in,out] pShell Receives the encoded instruction bytes.
		 * @param[in] rex The REX prefix byte.
		 * @param[in] opcode The register-specific opcode byte.
		 * @param[in] value The 64-bit immediate value to encode.
		 */
		static VOID AppendMovImm64(_Inout_ std::string* pShell, _In_ BYTE rex, _In_ BYTE opcode, _In_ DWORD64 value) {
			if ( !pShell ) return;
			BYTE shellcode[] = {
				rex, opcode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};
			*(DWORD64*) (shellcode + 2) = value;
			pShell->append((char*) shellcode, sizeof(shellcode));
		}

		/**
		 * @brief Emits the native x64 prologue.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		VOID onBackupEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;
			pShell->append((char*) Internal::backup_env, sizeof(Internal::backup_env));
		}

		/**
		 * @brief Emits the native x64 epilogue.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		VOID onRestoreEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;
			pShell->append((char*) Internal::restore_env, sizeof(Internal::restore_env));
		}
	};
	#endif // _WIN64
}
