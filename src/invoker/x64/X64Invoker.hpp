#pragma once
#include "../InvokerBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Invoker : public InvokerBase {
		protected:
		X64Invoker() : InvokerBase() {}

		VOID InjectPrepareEnv(_Inout_ std::string* pShell, _In_reads_(16) DWORD64* pArgs) {
			BYTE _prepare_env_temp[ sizeof(Internal::prepare_env) ];
			memcpy(_prepare_env_temp, Internal::prepare_env, sizeof(Internal::prepare_env));
			*(DWORD64*) (_prepare_env_temp + 2) = (DWORD64) pArgs;
			*(DWORD64*) (_prepare_env_temp + 12) = (DWORD64) 16;
			pShell->append((char*) _prepare_env_temp, sizeof(_prepare_env_temp));
		}

		virtual void onBackupEnv(_Inout_ std::string* pShell) override {
			pShell->append((char*) Internal::backup_env, sizeof(Internal::backup_env));
		}

		virtual void onRestoreEnv(_Inout_ std::string* pShell) override {
			pShell->append((char*) Internal::restore_env, sizeof(Internal::restore_env));
		}
	};
	#endif // _WIN64
}