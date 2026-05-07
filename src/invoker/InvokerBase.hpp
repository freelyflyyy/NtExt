#pragma once
#include "../internal/NtBase.hpp"
#include "../internal/NtResult.hpp"
#include "../internal/ScopeAction.hpp"

#include <cstring>
#include <string>

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

		virtual VOID onBackupEnv(_Inout_ std::string* Shell) = 0;
		virtual VOID onRestoreEnv(_Inout_ std::string* Shell) = 0;
		virtual VOID onPrepareEnv(_Inout_ std::string* pShell) {}
		virtual VOID onEmitOpcode(_Inout_ std::string* pShell) {}

		_Check_return_
			virtual NtStatus CompileRoutine(_Inout_ std::string* pShell) {
			if ( !pShell ) {
				return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid shell buffer.");
			}
			pShell->clear();
			onBackupEnv(pShell);
			onPrepareEnv(pShell);
			onEmitOpcode(pShell);
			onRestoreEnv(pShell);
			if ( pShell->empty() ) {
				return NtStatus::Failure(STATUS_UNSUCCESSFUL, L"Failed to compile shell routine.");
			}
			return NtStatus::Success();
		}

		public:
		_Check_return_
			NtResult<DWORD64> Invoke() {
			auto status = CompileRoutine(&_shellcode);
			if ( !status ) {
				return NtResult<DWORD64>::Failure(status);
			}

			LPVOID pExecuteMemory = VirtualAlloc(NULL, _shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if ( !pExecuteMemory ) {
				return NtResult<DWORD64>::Failure(STATUS_NO_MEMORY, L"VirtualAlloc failed.");
			}

			NTEXT_DEFER {
				VirtualFree(pExecuteMemory, 0, MEM_RELEASE);
			};

			memcpy(pExecuteMemory, _shellcode.data(), _shellcode.size());
			DWORD oldProtect;
			if ( !VirtualProtect(pExecuteMemory, _shellcode.size(), PAGE_EXECUTE_READ, &oldProtect) ) {
				return NtResult<DWORD64>::Failure(STATUS_ACCESS_DENIED, L"VirtualProtect failed.");
			}

			auto FnExecuteCode = (DWORD64(*)()) pExecuteMemory;
			const DWORD64 result = FnExecuteCode();
			return NtResult<DWORD64>::Success(result);
		}
	};
}
