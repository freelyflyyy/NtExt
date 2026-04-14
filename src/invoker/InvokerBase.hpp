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

	class InvokerBase {
		public:
		virtual ~InvokerBase() = default;

		InvokerBase(const InvokerBase&) = delete;
		InvokerBase& operator=(const InvokerBase&) = delete;

		protected:
		InvokerBase() = default;

		std::string _shellcode;

		virtual VOID onBackupEnv(_Inout_ std::string* pShell) = 0;
		virtual VOID onRestoreEnv(_Inout_ std::string* pShell) = 0;
		virtual VOID onPrepareEnv(_Inout_ std::string* pShell) {}
		virtual VOID onEmitOpcode(_Inout_ std::string* pShell) {}

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
