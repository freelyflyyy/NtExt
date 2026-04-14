#pragma once
#include "../InvokerBase.hpp"

namespace NtExt {
	#ifdef _M_IX86
	namespace Internal {
		static constexpr BYTE backup_env_x86[] = {
			0x55,                                                        // push ebp
			0x89, 0xE5,                                                  // mov ebp, esp
			0x0F, 0xA0,                                                  // push fs
			0x66, 0xB8, 0x2B, 0x00,                                      // mov ax, 0x2B
			0x8E, 0xE0,                                                  // mov fs, ax 
			0x83, 0xE4, 0xF0                                             // and esp, 0xFFFFFFF0 
		};

		static constexpr BYTE restore_env_x86[] = {
			0x8C, 0xD9,                                                  // mov cx, ds
			0x8E, 0xD1,                                                  // mov ss, cx
			0x8D, 0x65, 0xFC,                                            // lea esp,
			0x0F, 0xA1,                                                  // pop fs
			0x89, 0xEC,                                                  // mov esp, ebp
			0x5D,                                                        // pop ebp
			0xC3                                                         // ret
		};

		static constexpr BYTE jmp_x64[] = {
			0x6A, 0x33,                                                  // push 0x33
			0xE8, 0x00, 0x00, 0x00, 0x00,                                // call $+5
			0x83, 0x04, 0x24, 0x05,                                      // add dword ptr [esp], 5
			0xCB                                                         // retf
		};

		static constexpr BYTE jmp_x86[] = {
			0xE8, 0x00, 0x00, 0x00, 0x00,                                // call $+5              
			0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,              // mov dword [rsp+4], 0x23
			0x83, 0x04, 0x24, 0x0D,                                      // add dword [rsp], 0x0D 
			0xCB,                                                        // retf 
		};
	}

	/**
	 * @class Wow64Invoker
	 * @brief Base class for 32-bit to 64-bit invocations performed through Heaven's Gate.
	 * @details The implementation switches from the x86 WoW64 context into x64 mode, executes the
	 *          generated payload, and then restores the original x86 execution state.
	 */
	class Wow64Invoker : public InvokerBase {
		protected:
		/**
		 * @brief Initializes the WoW64 invoker base.
		 */
		Wow64Invoker() : InvokerBase() {}

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
		 * @brief Emits the x86-to-x64 transition and register-save prologue.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		VOID onBackupEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;
			pShell->append((char*) Internal::backup_env_x86, sizeof(Internal::backup_env_x86));
			pShell->append((char*) Internal::jmp_x64, sizeof(Internal::jmp_x64));
			pShell->append((char*) NtExt::Internal::backup_env, sizeof(NtExt::Internal::backup_env));
		}

		/**
		 * @brief Emits the x64-to-x86 transition and register-restore epilogue.
		 * @param[in,out] pShell Receives the generated machine code.
		 */
		VOID onRestoreEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) return;
			pShell->append((char*) NtExt::Internal::restore_env, sizeof(NtExt::Internal::restore_env) - 1);
			pShell->append((char*) Internal::jmp_x86, sizeof(Internal::jmp_x86));
			pShell->append((char*) Internal::restore_env_x86, sizeof(Internal::restore_env_x86));
		}
	};
	#endif
}
