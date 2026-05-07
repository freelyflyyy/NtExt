#include "X64Resolver.hpp"
#include "../../internal/NtStructs.h"
#include "../../internal/ScopeAction.hpp"
#include "../../invoker/NtExtInvokers.hpp"

namespace NtExt {
	#ifdef _WIN64
	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::GetProcAddress64Impl(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) {
		if ( !ModuleBase || !FunctionName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base or function name.");
		}
		FARPROC procAddress = GetProcAddress((HMODULE) ModuleBase, FunctionName);
		if ( !procAddress ) {
			return NtResult<DWORD64>::Failure(STATUS_PROCEDURE_NOT_FOUND, L"Procedure not found.");
		}
		return NtResult<DWORD64>::Success((DWORD64) procAddress);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::GetSyscallNumber64(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) {
		if ( !ModuleBase || !FunctionName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base or function name.");
		}

		auto funcAddr64 = this->GetProcAddress64(ModuleBase, FunctionName);
		if ( !funcAddr64 ) {
			return NtResult<DWORD64>::Failure(funcAddr64);
		}

		auto _getSysPacked = [] (DWORD64 funcAddr) -> DWORD64 {
			BYTE* opcodes = (BYTE*) funcAddr;
			if ( opcodes[ 0 ] == 0x4C && opcodes[ 1 ] == 0x8B && opcodes[ 2 ] == 0xD1 && opcodes[ 3 ] == 0xB8 ) {
				WORD _ssn = opcodes[ 5 ] << 8 | opcodes[ 4 ];
				DWORD64 _syscallAddr = funcAddr + 0x12;
				return ((DWORD64) _ssn << 48) | _syscallAddr;
			}
			return 0;
		};

		auto _searchImpl = [&_getSysPacked] (auto&& self, DWORD64 upAddr, DWORD64 downAddr, WORD depth = 0) -> DWORD64 {
			if ( depth >= 500 ) {
				return 0;
			}
			DWORD64 _upPacked = _getSysPacked(upAddr);
			DWORD64 _downPacked = _getSysPacked(downAddr);
			if ( _upPacked != 0 && _downPacked != 0 ) {
				WORD _upSSN = (WORD) (_upPacked >> 48);
				WORD _downSSN = (WORD) (_downPacked >> 48);
				if ( _downSSN - _upSSN == depth * 2 ) {
					WORD _targetSsn = _upSSN + depth;
					DWORD64 _targetSyscallAddr = _upPacked & 0x0000FFFFFFFFFFFF;
					return ((DWORD64) _targetSsn << 48) | _targetSyscallAddr;
				}
			}
			return self(self, upAddr - 0x20, downAddr + 0x20, depth + 1);
		};

		DWORD64 basePacked = _getSysPacked(funcAddr64.Value());
		if ( basePacked ) {
			return NtResult<DWORD64>::Success(basePacked);
		}

		DWORD64 syscallContext = _searchImpl(_searchImpl, funcAddr64.Value() - 0x20, funcAddr64.Value() + 0x20, 1);
		if ( !syscallContext ) {
			return NtResult<DWORD64>::Failure(STATUS_NOT_FOUND, L"Syscall context not found.");
		}
		return NtResult<DWORD64>::Success(syscallContext);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::GetModuleLdrEntry64(_In_z_ PCWSTR ModuleName) {
		if ( !ModuleName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module name.");
		}
		auto* _peb64 = (PEB64*) GetPeb64();
		if ( !_peb64 || !_peb64->Ldr ) {
			return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"Loader data not found.");
		}

		auto _ldr64 = (PEB_LDR_DATA64*) _peb64->Ldr;
		DWORD64 head = _peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
		DWORD64 current = _ldr64->InLoadOrderModuleList.Flink;

		while ( head != current && current != 0 ) {
			auto entry = (LDR_DATA_TABLE_ENTRY64*) current;
			if ( entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0 ) {
				if ( !_wcsnicmp((WCHAR*) entry->BaseDllName.Buffer, ModuleName, entry->BaseDllName.Length / sizeof(WCHAR)) ) {
					return NtResult<DWORD64>::Success(current);
				}
			}
			current = entry->InLoadOrderLinks.Flink;
		}
		return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"Module not found.");
	}

	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::GetModuleBase64(_In_z_ PCWSTR ModuleName) {
		auto ldrEntry = GetModuleLdrEntry64(ModuleName);
		if ( !ldrEntry ) {
			return NtResult<DWORD64>::Failure(ldrEntry);
		}
		auto* entry = (LDR_DATA_TABLE_ENTRY64*) ldrEntry.Value();
		if ( !entry->DllBase ) {
			return NtResult<DWORD64>::Failure(STATUS_DLL_NOT_FOUND, L"Module base not found.");
		}
		return NtResult<DWORD64>::Success(entry->DllBase);
	}

	_Check_return_ _Success_(return != 0)
		DWORD64 NTAPI X64Resolver::GetTeb64() {
		return __readgsqword(FIELD_OFFSET(NT_TIB, Self));
	}

	_Check_return_ _Success_(return != 0)
		DWORD64 NTAPI X64Resolver::GetPeb64() {
		return __readgsqword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
	}

	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::GetNtdll64() {
		static DWORD64 _ntdll64 = 0;
		if ( _ntdll64 != 0 ) {
			return NtResult<DWORD64>::Success(_ntdll64);
		}
		auto moduleBase = GetModuleBase64(L"ntdll.dll");
		if ( !moduleBase ) {
			return NtResult<DWORD64>::Failure(moduleBase);
		}
		_ntdll64 = moduleBase.Value();
		return NtResult<DWORD64>::Success(_ntdll64);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::GetKernel64() {
		static DWORD64 _kernel64 = 0;
		if ( _kernel64 != 0 ) {
			return NtResult<DWORD64>::Success(_kernel64);
		}
		auto moduleBase = GetModuleBase64(L"kernel32.dll");
		if ( !moduleBase ) {
			return NtResult<DWORD64>::Failure(moduleBase);
		}
		_kernel64 = moduleBase.Value();
		return NtResult<DWORD64>::Success(_kernel64);
	}

	_Check_return_
		NtResult<DWORD64> NTAPI X64Resolver::LoadLibrary64(_In_z_ PCWSTR ModuleName) {
		if ( !ModuleName ) {
			return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module name.");
		}

		auto moduleBase = GetModuleBase64(ModuleName);
		if ( moduleBase ) {
			return moduleBase;
		}
		if ( moduleBase.Code() != STATUS_DLL_NOT_FOUND ) {
			return NtResult<DWORD64>::Failure(moduleBase);
		}

		auto ntdll64 = GetNtdll64();
		if ( !ntdll64 ) {
			return NtResult<DWORD64>::Failure(ntdll64);
		}
		static DWORD64 pLdrLoadDll = 0;
		if ( !pLdrLoadDll ) {
			auto ldrLoadDll = GetProcAddress64(ntdll64.Value(), "LdrLoadDll");
			if ( !ldrLoadDll ) {
				return NtResult<DWORD64>::Failure(ldrLoadDll);
			}
			pLdrLoadDll = ldrLoadDll.Value();
		}

		BYTE buffer[ 64 ] = { 0 };
		MakeUTFStr < DWORD64 >(ModuleName, buffer);
		DWORD64 loadedModule = { 0 };

		auto loadDll = Call(pLdrLoadDll)(
			(DWORD64) 0,
			(DWORD64) 0,
			(DWORD64) buffer,
			(DWORD64) &loadedModule
			);

		if ( !loadDll ) {
			return NtResult<DWORD64>::Failure(loadDll);
		}

		NTSTATUS status = (NTSTATUS) loadDll.Value();
		if ( !NT_SUCCESS(status) ) {
			return NtResult<DWORD64>::Failure(status, L"LdrLoadDll failed.");
		}
		if ( !loadedModule ) {
			return NtResult<DWORD64>::Failure(STATUS_UNSUCCESSFUL, L"LdrLoadDll returned an empty module base.");
		}
		return NtResult<DWORD64>::Success(loadedModule);
	}

	_Check_return_
		NtStatus NTAPI X64Resolver::MapKnownDllSection64(_In_z_ PCWSTR DllName, _Out_ DWORD64* MappedBase, _Out_opt_ DWORD64* ViewSize) {
		if ( !MappedBase ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid mapped base output.");
		}
		*MappedBase = 0;
		if ( !DllName ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid DLL name.");
		}
		if ( ViewSize ) {
			*ViewSize = 0;
		}

		WCHAR knownDllPath[ MAX_PATH ] = L"\\KnownDlls\\";
		SIZE_T pathOffset = 11;

		for ( SIZE_T i = 0; DllName[ i ] != L'\0'; ++i ) {
			if ( pathOffset + 1 >= MAX_PATH ) {
				return NtStatus::Failure(STATUS_NAME_TOO_LONG, L"KnownDll path is too long.");
			}
			knownDllPath[ pathOffset++ ] = DllName[ i ];
		}
		knownDllPath[ pathOffset ] = L'\0';

		auto ntdllBase = GetNtdll64();
		if ( !ntdllBase ) {
			return NtStatus::Failure(ntdllBase);
		}
		auto ntOpenSection = GetSyscallNumber64(ntdllBase.Value(), "NtOpenSection");
		if ( !ntOpenSection ) {
			return NtStatus::Failure(ntOpenSection);
		}
		auto ntMapViewOfSection = GetSyscallNumber64(ntdllBase.Value(), "NtMapViewOfSection");
		if ( !ntMapViewOfSection ) {
			return NtStatus::Failure(ntMapViewOfSection);
		}
		auto ntClose = GetSyscallNumber64(ntdllBase.Value(), "NtClose");
		if ( !ntClose ) {
			return NtStatus::Failure(ntClose);
		}

		BYTE sectionName[ sizeof(UNICODE_STRING64) + MAX_PATH * sizeof(WCHAR) ] = { 0 };
		MakeUTFStr<DWORD64>(knownDllPath, sectionName);

		OBJECT_ATTRIBUTES64 objectAttributes = { 0 };
		InitializeObjectAttributesEx64(
			&objectAttributes,
			&sectionName,
			OBJ_CASE_INSENSITIVE,
			0,
			0
		);

		DWORD64 hSection = 0;
		DWORD64 mappedBase = 0;
		DWORD64 viewSize = 0;

		auto openSection = Syscall(ntOpenSection.Value())(
			(DWORD64) &hSection,
			SECTION_MAP_READ,
			(DWORD64) &objectAttributes
			);
		if ( openSection.Failed() ) {
			return openSection;
		}
		if ( !hSection ) {
			return NtStatus::Failure(STATUS_INVALID_HANDLE, L"NtOpenSection returned an empty handle.");
		}

		NTEXT_DEFER{
			(VOID) Syscall(ntClose.Value())(hSection);
		};

		auto mapView = Syscall(ntMapViewOfSection.Value())(
			hSection,
			(DWORD64) -1,
			(DWORD64) &mappedBase,
			0, 0, 0,
			(DWORD64) &viewSize,
			ViewUnmap, 0,
			PAGE_READONLY
			);
		if ( mapView.Failed() ) {
			return mapView;
		}
		if ( !mappedBase ) {
			return NtStatus::Failure(STATUS_UNSUCCESSFUL, L"NtMapViewOfSection returned an empty base.");
		}

		*MappedBase = mappedBase;
		if ( ViewSize ) {
			*ViewSize = viewSize;
		}
		return NtStatus::Success();
	}

	_Check_return_
		NtStatus NTAPI X64Resolver::UnmapKnownDllSection64(_In_ DWORD64 MappedBase) {
		if ( !MappedBase ) {
			return NtStatus::Failure(STATUS_INVALID_PARAMETER, L"Invalid mapped base.");
		}
		auto ntdllBase = GetNtdll64();
		if ( !ntdllBase ) {
			return NtStatus::Failure(ntdllBase);
		}
		auto ntUnmapViewOfSection = GetSyscallNumber64(ntdllBase.Value(), "NtUnmapViewOfSection");
		if ( !ntUnmapViewOfSection ) {
			return NtStatus::Failure(ntUnmapViewOfSection);
		}

		auto unmapView = Syscall(ntUnmapViewOfSection.Value())(
			(DWORD64) -1,
			MappedBase
			);
		if ( unmapView.Failed() ) {
			return unmapView;
		}
		return NtStatus::Success();
	}
	#endif
}
