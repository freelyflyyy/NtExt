#pragma once
#include "../InvokerBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Invoker : public InvokerBase {
		protected:
		X64Invoker(DWORD64 target) : InvokerBase(target) {}

		private:
		virtual BOOL CompileRoutine(_Inout_ std::string* pShell) override {
			if ( !pShell ) return FALSE;

			BYTE _prepare_env_temp[ sizeof(Internal::prepare_env) ];
			memcpy(_prepare_env_temp, Internal::prepare_env, sizeof(Internal::prepare_env));
			*(DWORD64*) (_prepare_env_temp + 2) = (DWORD64) _global_args;
			*(DWORD64*) (_prepare_env_temp + 12) = (DWORD64) 16;

			//bytecode concatenation
			pShell->append((char*) Internal::backup_env, sizeof(Internal::backup_env));                  // backup x64 envirenment
			pShell->append((char*) _prepare_env_temp, sizeof(_prepare_env_temp));                        // push the parameters onto the stack
			EmitOpcode(pShell);                                                                          // splice call function method
			pShell->append((char*) Internal::restore_env, sizeof(Internal::restore_env));                // restore x64 envirenment
			return TRUE;
		}
	};
	#endif // _WIN64
}