#pragma once
#include "../InvokerBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Invoker : public InvokerBase {
		protected:
		X64Invoker() : InvokerBase() {}

		static VOID AppendMovImm64(_Inout_ std::string* pShell, _In_ BYTE rex, _In_ BYTE opcode, _In_ DWORD64 value) {
			if ( !pShell ) {
				return;
			}
			BYTE shellcode[] = {
				rex, opcode, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
			};
			*(DWORD64*) (shellcode + 2) = value;
			pShell->append((char*) shellcode, sizeof(shellcode));
		}

		VOID onBackupEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) {
				return;
			}
			pShell->append((char*) Internal::backup_env, sizeof(Internal::backup_env));
		}

		VOID onRestoreEnv(_Inout_ std::string* pShell) override {
			if ( !pShell ) {
				return;
			}
			pShell->append((char*) Internal::restore_env, sizeof(Internal::restore_env));
		}
	};
	#endif // _WIN64
}
