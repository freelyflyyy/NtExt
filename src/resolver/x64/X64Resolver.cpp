#include "X64Resolver.hpp"
#include "../../internal/NtStructs.h"
#include "../../invoker/NtExtInvokers.hpp"

namespace NtExt {
	namespace Resolver {
		#ifdef _WIN64
		namespace detail {
			std::unordered_map<std::string, DWORD64> _cache;
			std::shared_mutex _mutex;

			DWORD64 NTAPI GetProcAddress64Impl(_In_ DWORD64 hMod, _In_z_ const char* funcName) {
				if ( !hMod || !funcName ) return 0;
				return (DWORD64) GetProcAddress((HMODULE) hMod, funcName);
			}

			VOID NTAPI MakeUTFStrImpl(_In_z_ LPCWSTR lpString, _Out_writes_bytes_(pointerSize + wcslen(lpString) * sizeof(WCHAR) + 16) LPBYTE outBuffer, _In_ SIZE_T pointerSize) {
				if ( !lpString || !outBuffer ) return;
				SIZE_T len = wcslen(lpString);
				*(USHORT*) (outBuffer) = (USHORT) len * sizeof(WCHAR);
				*(USHORT*) (outBuffer + 2) = (USHORT) (len + 1) * sizeof(WCHAR);
				WCHAR* outStr;
				if ( pointerSize == 8 ) {
					outStr = (WCHAR*) (outBuffer + 16);
					*(DWORD64*) (outBuffer + 8) = (DWORD64) outStr;
				} else if ( pointerSize == 4 ) {
					outStr = (WCHAR*) (outBuffer + 8);
					*(DWORD*) (outBuffer + 4) = (DWORD) (SIZE_T) outStr;
				} else { return; }
				for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = lpString[ i ];
				outStr[ len ] = L'\0';
			}

			VOID NTAPI MakeANSIStrImpl(_In_z_ LPCSTR lpString, _Out_writes_bytes_(pointerSize + strlen(lpString) + 16) LPBYTE outBuffer, _In_ SIZE_T pointerSize) {
				if ( !lpString || !outBuffer ) return;
				SIZE_T len = strlen(lpString);
				*(USHORT*) (outBuffer) = (USHORT) len;
				*(USHORT*) (outBuffer + 2) = (USHORT) (len + 1);
				char* outStr;
				if ( pointerSize == 8 ) {
					outStr = (char*) (outBuffer + 16);
					*(DWORD64*) (outBuffer + 8) = (DWORD64) outStr;
				} else if ( pointerSize == 4 ) {
					outStr = (char*) (outBuffer + 8);
					*(DWORD*) (outBuffer + 4) = (DWORD) (SIZE_T) outStr;
				} else { return; }
				for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = lpString[ i ];
				outStr[ len ] = '\0';
			}
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) {
			if ( !hMod || !funcName ) return 0;
			DWORD64 funcAddr64 = GetProcAddress64(hMod, funcName);
			if ( !funcAddr64 ) return 0;

			auto _getSysPacked = [] (DWORD64 funcAddr) -> DWORD64 {
				BYTE* opcodes = (BYTE*) funcAddr;
				if ( opcodes[ 0 ] == 0x4C && opcodes[ 1 ] == 0x8B && opcodes[ 2 ] == 0xD1 && opcodes[ 3 ] == 0xB8 ) {
					WORD _ssn = opcodes[ 5 ] << 8 | opcodes[ 4 ];
					DWORD64 _syscallAddr = funcAddr + 8;
					return ((DWORD64) _ssn << 48) | _syscallAddr;
				}
				return 0;
			};

			auto _searchImpl = [&_getSysPacked] (auto&& self, DWORD64 upAddr, DWORD64 downAddr, WORD depth = 0) -> DWORD64 {
				if ( depth >= 500 ) return 0;
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

			DWORD64 basePacked = _getSysPacked(funcAddr64);
			if ( basePacked != 0 ) return basePacked;

			return _searchImpl(_searchImpl, funcAddr64 - 0x20, funcAddr64 + 0x20, 1);
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) {
			if ( !moduleName ) return 0;
			auto* _peb64 = (PEB64*) GetPeb64();
			if ( !_peb64->Ldr ) return 0;

			auto _ldr64 = (PEB_LDR_DATA64*) _peb64->Ldr;
			DWORD64 head = _peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
			DWORD64 current = _ldr64->InLoadOrderModuleList.Flink;

			while ( head != current && current != 0 ) {
				auto entry = (LDR_DATA_TABLE_ENTRY64*) current;
				if ( entry->BaseDllName.Buffer != 0 && entry->BaseDllName.Length > 0 ) {
					if ( !_wcsnicmp((WCHAR*) entry->BaseDllName.Buffer, moduleName, entry->BaseDllName.Length / sizeof(WCHAR)) ) {
						return current;
					}
				}
				current = entry->InLoadOrderLinks.Flink;
			}
			return 0;
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) {
			if ( !moduleName ) return 0;
			auto* entry = (LDR_DATA_TABLE_ENTRY64*) GetModuleLdrEntry64(moduleName);
			if ( !entry ) return 0;
			return entry->DllBase;
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetTeb64() {
			return __readgsqword(offsetof(NT_TIB64, Self));
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetPeb64() {
			return __readgsqword(offsetof(TEB64, ProcessEnvironmentBlock));
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetNtdll64() {
			static DWORD64 _ntdll64 = 0;
			if ( _ntdll64 != 0 ) return _ntdll64;
			_ntdll64 = (DWORD64) GetModuleBase64(L"ntdll.dll");
			return _ntdll64;
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetKernel64() {
			static DWORD64 _kernel64 = 0;
			if ( _kernel64 != 0 ) return _kernel64;
			_kernel64 = (DWORD64) GetModuleBase64(L"kernel32.dll");
			return _kernel64;
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) {
			if ( !moduleName ) return 0;

			DWORD64 hMod = GetModuleBase64(moduleName);
			if ( hMod != 0 ) return hMod;

			DWORD64 pLdrLoadDll = GetProcAddress64(GetNtdll64(), "LdrLoadDll");
			if ( !pLdrLoadDll ) return 0;

			BYTE buffer[ 64 ] = { 0 };
			MakeUTFStr < DWORD64 >(moduleName, buffer);
			DWORD64 hResult = { 0 };

			NTSTATUS status = Call(pLdrLoadDll)(
				(DWORD64) 0,
				(DWORD64) 0,
				(DWORD64) buffer,
				(DWORD64) &hResult
				);

			if ( NT_SUCCESS(status) ) return hResult;
			return status;
		}

		_Success_(return != 0)
			DWORD64 IsCached64(_In_ const std::string& funcName) {
			std::shared_lock<std::shared_mutex> lock(detail::_mutex);
			auto it = detail::_cache.find(funcName);
			if ( it != detail::_cache.end() ) return it->second;
			return 0;
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 GetProcAddress64(_In_ DWORD64 hMod, _In_ const std::string& funcName) {
			if ( auto addr = IsCached64(funcName) ) return addr;
			if ( hMod == 0 ) return 0;
			DWORD64 procAddr = detail::GetProcAddress64Impl(hMod, funcName.data());
			if ( procAddr ) {
				std::unique_lock<std::shared_mutex> lock(detail::_mutex);
				detail::_cache[ funcName ] = procAddr;
			}
			return procAddr;
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 GetProcAddress64(_In_ const std::wstring& moduleName, _In_ const std::string& funcName) {
			if ( auto addr = IsCached64(funcName) ) return addr;
			DWORD64 hMod = GetModuleBase64(moduleName.data());
			if ( hMod == 0 ) return 0;
			return GetProcAddress64(hMod, funcName);
		}

		_Check_return_ _Success_(return != 0)
			DWORD64 GetProcAddress64(_In_ const std::string& funcName) {
			if ( auto addr = IsCached64(funcName) ) return addr;
			return GetProcAddress64(GetNtdll64(), funcName);
		}
		#endif
	}
}
