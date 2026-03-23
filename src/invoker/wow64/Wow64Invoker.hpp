#pragma once
#include "../InvokerBase.hpp"

namespace NtExt {
	#ifdef _M_IX86
	namespace Internal {
		static constexpr BYTE backup_env_x86[] = {
			0x55,                                                        // push ebp
			0x53,                                                        // push ebx
			0x56,                                                        // push esi
			0x57                                                         // push edi
		};

		static constexpr BYTE restore_env_x86[] = {
			0x5F,                                                        // pop edi
			0x5E,                                                        // pop esi
			0x5B,                                                        // pop ebx
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
			0x48, 0x89, 0xC2,                                            // mov rdx, rax
			0x48, 0xC1, 0xEA, 0x20,                                      // shr rdx, 32
			0xE8, 0x00, 0x00, 0x00, 0x00,                                // call $+5              
			0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,              // mov dword [rsp+4], 0x2
			0x83, 0x04, 0x24, 0x0D,                                      // add dword [rsp], 0x0D 
			0xCB,                                                        // retf 
		};
	}

	class Wow64Invoker : public InvokerBase {
		protected:
		Wow64Invoker() : InvokerBase() {}

		VOID InjectPrepareEnv(_Inout_ std::string* pShell, _In_reads_(16) DWORD64* pArgs) {
			BYTE _prepare_env_temp[ sizeof(Internal::prepare_env) ];
			memcpy(_prepare_env_temp, Internal::prepare_env, sizeof(Internal::prepare_env));
			*(DWORD64*) (_prepare_env_temp + 2) = (DWORD64) pArgs;
			*(DWORD64*) (_prepare_env_temp + 12) = (DWORD64) 16;
			pShell->append((char*) _prepare_env_temp, sizeof(_prepare_env_temp));
		}

		virtual void onBackupEnv(_Inout_ std::string* pShell) override {
			pShell->append((char*) Internal::backup_env_x86, sizeof(Internal::backup_env_x86));
			pShell->append((char*) Internal::jmp_x64, sizeof(Internal::jmp_x64));
			pShell->append((char*) Internal::backup_env, sizeof(Internal::backup_env));
		}

		virtual void onRestoreEnv(_Inout_ std::string* pShell) override {
			pShell->append((char*) Internal::restore_env, sizeof(Internal::restore_env) - 1);
			pShell->append((char*) Internal::jmp_x86, sizeof(Internal::jmp_x86));
			pShell->append((char*) Internal::restore_env_x86, sizeof(Internal::restore_env_x86));
		}
	};
	#endif
}