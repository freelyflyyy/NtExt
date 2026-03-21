#pragma once
#include "X64NtCallExt.h"
#include "internal/NtAsm.h"

namespace NtExt {
	DWORD64 NTAPI X64NtCallExt::GetProcAddress64(DWORD64 hMod, const char* funcName) {
		if ( !hMod || !funcName ) {
			return 0;
		}
		return (DWORD64) GetProcAddress((HMODULE) hMod, funcName);
	}

	DWORD64 X64NtCallExt::GetSyscallNumber64(DWORD64 hMod, const char* funcName) {
		if ( !hMod || !funcName ) return 0;
		DWORD64 funcAddr64 = GetProcAddress64(hMod, funcName);
		if ( !funcAddr64 ) return 0;

		//check the function addr was hooked
		auto CheckHook = [this] (DWORD64& funcAddr) -> WORD {
			BYTE* opcodes = (BYTE*) funcAddr;
			if ( opcodes[ 0 ] == 0x4C && opcodes[ 1 ] == 0x8B && opcodes[ 2 ] == 0xD1 && opcodes[ 3 ] == 0xB8 ) {
				return opcodes[ 5 ] << 8 | opcodes[ 4 ];
			}
			return 0;
		};

		auto _seachImpl = [CheckHook] (auto&& self, DWORD64 upAddr, DWORD64 downAddr, WORD depth = 0) -> WORD {
			if ( depth >= 500 ) return 0;

			WORD upSSN = CheckHook(upAddr);
			WORD downSSN = CheckHook(downAddr);

			if ( upSSN != 0 && downSSN != 0 ) {
				if ( downSSN - upSSN == depth * 2 ) {
					return upSSN + depth;
				}
			}
			return self(self, upAddr - 0x20, downAddr + 0x20, depth + 1);
		};

		//check the function self was hooked
		WORD baseSSN = CheckHook(funcAddr64);
		if ( baseSSN != 0 ) {
			return baseSSN;
		}

		return _seachImpl(_seachImpl, funcAddr64 - 0x20, funcAddr64 + 0x20, 1);
	}

	DWORD64 NTAPI X64NtCallExt::GetModuleLdrEntry64(const wchar_t* moduleName) {
		if ( !moduleName ) return 0;
		PEB64* _peb64 = (PEB64*) GetPeb64();
		if ( !_peb64->Ldr ) {
			return 0;
		}
		PEB_LDR_DATA64* _ldr64 = (PEB_LDR_DATA64*) _peb64->Ldr;
		DWORD64 head = _peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
		DWORD64 current = _ldr64->InLoadOrderModuleList.Flink;
		while ( head != current && current != 0 ) {
			LDR_DATA_TABLE_ENTRY64* entry = (LDR_DATA_TABLE_ENTRY64*) current;
			if ( entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0 ) {
				if ( !_wcsnicmp((WCHAR*) entry->BaseDllName.Buffer, moduleName, entry->BaseDllName.Length / sizeof(WCHAR)) ) {
					return current;
				}
			}
			current = entry->InLoadOrderLinks.Flink;
		}
		return 0;
	}

	DWORD64 NTAPI X64NtCallExt::GetModuleBase64(const wchar_t* moduleName) {
		if ( !moduleName ) {
			return 0;
		}
		LDR_DATA_TABLE_ENTRY64* entry = (LDR_DATA_TABLE_ENTRY64*) GetModuleLdrEntry64(moduleName);
		return entry->DllBase;
	}

	DWORD64 NTAPI X64NtCallExt::GetNtdll64() {
		static DWORD64 _ntdll64 = 0;
		if ( _ntdll64 != 0 ) {
			return _ntdll64;
		}
		_ntdll64 = (DWORD64) GetModuleBase64(L"ntdll.dll");
		return _ntdll64;
	}

	DWORD64 NTAPI X64NtCallExt::GetKernel64() {
		static DWORD64 _kernel64 = 0;
		if ( _kernel64 != 0 ) {
			return _kernel64;
		}
		_kernel64 = (DWORD64) GetModuleBase64(L"kernel32.dll");
		return _kernel64;
	}

	DWORD64 NTAPI X64NtCallExt::LoadLibrary64(const wchar_t* moduleName) {
		if ( !moduleName ) return 0;

		DWORD64 hMod = GetModuleBase64(moduleName);
		if ( hMod != 0 ) return hMod;

		static DWORD64 pLdrLoadDll = 0;
		if ( !pLdrLoadDll ) {
			pLdrLoadDll = GetProcAddress64(GetNtdll64(), "LdrLoadDll");
		}
		if ( !pLdrLoadDll ) return 0;

		BYTE buffer[ 64 ] = { 0 };
		MakeUTFStr < DWORD64 >(moduleName, buffer);

		DWORD64 hResult = { 0 };
		NTSTATUS status = X64Call(pLdrLoadDll, (DWORD64) 0, (DWORD64) 0, (DWORD64) buffer, (DWORD64) &hResult);

		if ( NT_SUCCESS(status) ) {
			return hResult;
		}

		return status;
	}

	DWORD64 NTAPI X64NtCallExt::GetTeb64() {
		Reg64 _teb64 = { 0 };
		#ifdef _WIN64
		_teb64.v = __readgsqword(FIELD_OFFSET(NT_TIB, Self));
		#endif
		return _teb64.v;
	}

	DWORD64 NTAPI X64NtCallExt::GetPeb64() {
		Reg64 _peb64 = { 0 };
		#ifdef _WIN64
		_peb64.v = __readgsqword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
		#endif
		return _peb64.v;
	}

	DWORD64 X64NtCallExt::_X64BuildExecute(std::function<void(std::string&)> _shellcode, const DWORD64* _pParam, const DWORD& _argC) {
		*(DWORD64*) (prepare_env + 2) = (DWORD64) _pParam;
		*(DWORD64*) (prepare_env + 12) = (DWORD64) _argC;

		std::string shellcode;
		shellcode.append((char*) backup_env, sizeof(backup_env));
		shellcode.append((char*) prepare_env, sizeof(prepare_env));
		_shellcode(shellcode);
		shellcode.append((char*) restore_env, sizeof(restore_env));

		return _X64DisptachExecute(shellcode);
	}
	DWORD64 X64NtCallExt::_X64DisptachExecute(std::string _shellcode) {
		if ( _shellcode.empty() ) return 0;
		DWORD64 result;
		#ifdef _WIN64
		LPVOID pExecuteMemory = VirtualAlloc(
			NULL,
			_shellcode.size(),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
		if ( !pExecuteMemory ) return 0;
		memcpy(pExecuteMemory, _shellcode.data(), _shellcode.size());
		auto FnExecuteCode = (DWORD64(*)()) pExecuteMemory;

		result = FnExecuteCode();
		VirtualFree(pExecuteMemory, 0, MEM_RELEASE);
		#endif
		return result;
	}
}