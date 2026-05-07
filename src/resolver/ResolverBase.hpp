#pragma once
#include "../internal/NtBase.hpp"
#include "../internal/NtResult.hpp"

#include <cstring>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace NtExt {

	class ResolverBase {
		public:
		virtual ~ResolverBase() = default;

		ResolverBase(const ResolverBase&) = delete;
		ResolverBase& operator=(const ResolverBase&) = delete;

		/**
		 * @brief Dynamically locates the System Service Number (SSN) for an NTAPI function.
		 * @param[in] ModuleBase The 64-bit base address of the module, for example ntdll.dll.
		 * @param[in] FunctionName The exported NTAPI function name, for example "NtReadVirtualMemory".
		 * @return An NtResult containing the packed SSN and syscall address on success.
		 */
		_Check_return_
			virtual NtResult<DWORD64> NTAPI GetSyscallNumber64(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) = 0;

		/**
		 * @brief Retrieves the LDR_DATA_TABLE_ENTRY address for a loaded module by traversing the 64-bit PEB.
		 * @param[in] ModuleName The wide-character module name, for example L"ntdll.dll".
		 * @return An NtResult containing the 64-bit LDR entry address on success.
		 */
		_Check_return_
			virtual NtResult<DWORD64> NTAPI GetModuleLdrEntry64(_In_z_ PCWSTR ModuleName) = 0;

		/**
		 * @brief Retrieves the 64-bit base address of a loaded module.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 64-bit module base address on success.
		 */
		_Check_return_
			virtual NtResult<DWORD64> NTAPI GetModuleBase64(_In_z_ PCWSTR ModuleName) = 0;

		/**
		 * @brief Gets the 64-bit address of the Thread Environment Block (TEB).
		 * @return The 64-bit TEB address.
		 */
		_Check_return_ _Success_(return != 0)
			virtual DWORD64 NTAPI GetTeb64() = 0;

		/**
		 * @brief Gets the 64-bit address of the Process Environment Block (PEB).
		 * @return The 64-bit PEB address.
		 */
		_Check_return_ _Success_(return != 0)
			virtual DWORD64 NTAPI GetPeb64() = 0;

		/**
		 * @brief Retrieves the 64-bit base address of ntdll.dll.
		 * @return An NtResult containing the 64-bit base address of ntdll.dll on success.
		 */
		_Check_return_
			virtual NtResult<DWORD64> NTAPI GetNtdll64() = 0;

		/**
		 * @brief Retrieves the 64-bit base address of kernel32.dll.
		 * @return An NtResult containing the 64-bit base address of kernel32.dll on success.
		 */
		_Check_return_
			virtual NtResult<DWORD64> NTAPI GetKernel64() = 0;

		/**
		 * @brief Manually loads a library into the 64-bit address space using LdrLoadDll.
		 * @param[in] ModuleName The wide-character module name to load.
		 * @return An NtResult containing the 64-bit base address of the loaded module on success.
		 */
		_Check_return_
			virtual NtResult<DWORD64> NTAPI LoadLibrary64(_In_z_ PCWSTR ModuleName) = 0;

		/**
		 * @brief Constructs a UNICODE_STRING-like structure in the provided buffer.
		 * @tparam T The pointer-sized field type, such as DWORD or DWORD64.
		 * @param[in] lpString The null-terminated wide string to package.
		 * @param[out] outBuffer The pre-allocated buffer that receives the structure header and string data.
		 */
		template<typename T>
		VOID MakeUTFStr(_In_z_ LPCWSTR lpString, _Out_writes_bytes_all_(sizeof(T) + wcslen(lpString) * 2 + 16) LPBYTE outBuffer) {
			MakeUTFStrImpl(lpString, outBuffer, sizeof(T));
		}

		/**
		 * @brief Converts an ANSI string to a wide string and constructs a UNICODE_STRING-like structure.
		 * @tparam T The pointer-sized field type, such as DWORD or DWORD64.
		 * @param[in] lpString The null-terminated ANSI string to convert.
		 * @param[out] outUnicodeStr The pre-allocated output buffer for the resulting structure.
		 */
		template<typename T>
		VOID MakeUTFStr(_In_z_ LPCSTR lpString, _Out_ LPBYTE outUnicodeStr) {
			int len = MultiByteToWideChar(CP_ACP, 0, lpString, -1, NULL, 0);
			std::wstring wStr(len, L'\0');
			MultiByteToWideChar(CP_ACP, 0, lpString, -1, wStr.data(), len);
			MakeUTFStr<T>(wStr.c_str(), outUnicodeStr);
		}

		/**
		 * @brief Constructs an ANSI_STRING-like structure in the provided buffer.
		 * @tparam T The pointer-sized field type, such as DWORD or DWORD64.
		 * @param[in] lpString The null-terminated ANSI string to package.
		 * @param[out] outBuffer The pre-allocated buffer that receives the structure header and string data.
		 */
		template<typename T>
		VOID MakeANSIStr(_In_z_ LPCSTR lpString, _Out_writes_bytes_all_(sizeof(T) + strlen(lpString) + 16) LPBYTE outBuffer) {
			MakeANSIStrImpl(lpString, outBuffer, sizeof(T));
		}

		/**
		 * @brief Converts a wide string to an ANSI string and constructs an ANSI_STRING-like structure.
		 * @tparam T The pointer-sized field type, such as DWORD or DWORD64.
		 * @param[in] lpString The null-terminated wide string to convert.
		 * @param[out] outAnsiStr The pre-allocated output buffer for the resulting structure.
		 */
		template<typename T>
		VOID MakeANSIStr(_In_z_ LPCWSTR lpString, _Out_ LPBYTE outAnsiStr) {
			int len = WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL);
			std::string aStr(len, '\0');
			WideCharToMultiByte(CP_ACP, 0, lpString, -1, aStr.data(), len, NULL, NULL);
			MakeANSIStr<T>(aStr.c_str(), outAnsiStr);
		}

		/**
		 * @brief Thread-safely checks whether a 64-bit exported function address is cached.
		 * @param[in] funcName The exported function name.
		 * @param[out] Address Receives the cached 64-bit address when the function returns TRUE.
		 * @return TRUE when a cached address was found; otherwise FALSE.
		 */
		_Check_return_ _Success_(return != FALSE)
			BOOL IsCached64(_In_ const std::string& funcName, _Out_ DWORD64* Address) {
			if ( !Address ) {
				return FALSE;
			}
			*Address = 0;
			std::shared_lock<std::shared_mutex> lock(_mutex64);
			auto it = _cache64.find(funcName);
			if ( it == _cache64.end() || !it->second ) {
				return FALSE;
			}
			*Address = it->second;
			return TRUE;
		}

		/**
		 * @brief Retrieves the 64-bit address of an exported function and caches successful lookups.
		 * @param[in] ModuleBase The 64-bit module base address.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD64> GetProcAddress64(_In_ DWORD64 ModuleBase, _In_ const std::string& FunctionName) {
			DWORD64 cachedAddr = 0;
			if ( IsCached64(FunctionName, &cachedAddr) ) {
				return NtResult<DWORD64>::Success(cachedAddr);
			}
			if ( !ModuleBase ) {
				return NtResult<DWORD64>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base.");
			}

			auto procAddr = GetProcAddress64Impl(ModuleBase, FunctionName.data());
			if ( procAddr ) {
				std::unique_lock<std::shared_mutex> lock(_mutex64);
				_cache64[ FunctionName ] = procAddr.Value();
			}
			return procAddr;
		}

		/**
		 * @brief Retrieves the 64-bit address of an exported function by module name.
		 * @param[in] ModuleName The wide-character module name.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD64> GetProcAddress64(_In_ const std::wstring& ModuleName, _In_ const std::string& FunctionName) {
			DWORD64 cachedAddr = 0;
			if ( IsCached64(FunctionName, &cachedAddr) ) {
				return NtResult<DWORD64>::Success(cachedAddr);
			}

			auto moduleBase = GetModuleBase64(ModuleName.data());
			if ( !moduleBase ) {
				return NtResult<DWORD64>::Failure(moduleBase);
			}
			return GetProcAddress64(moduleBase.Value(), FunctionName);
		}

		/**
		 * @brief Retrieves the 64-bit address of an exported function from the 64-bit ntdll.dll.
		 * @param[in] FunctionName The exported function name expected in ntdll.dll.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD64> GetProcAddress64(_In_ const std::string& FunctionName) {
			auto ntdll64 = GetNtdll64();
			if ( !ntdll64 ) {
				return NtResult<DWORD64>::Failure(ntdll64);
			}
			return GetProcAddress64(ntdll64.Value(), FunctionName);
		}

		/**
		 * @brief Maps a KnownDll section into the current process as a 64-bit view.
		 * @param[in] DllName The KnownDll name to map.
		 * @param[out] MappedBase Receives the mapped 64-bit base address on success.
		 * @param[out] ViewSize Optional pointer that receives the mapped view size.
		 * @return NtStatus::Success on success; failure status otherwise.
		 */
		_Check_return_
			virtual NtStatus NTAPI MapKnownDllSection64(_In_z_ PCWSTR DllName, _Out_ DWORD64* MappedBase, _Out_opt_ DWORD64* ViewSize = nullptr) = 0;

		/**
		 * @brief Unmaps a 64-bit KnownDll section view previously mapped by MapKnownDllSection64.
		 * @param[in] MappedBase The mapped 64-bit base address.
		 * @return NtStatus::Success on success; failure status otherwise.
		 */
		_Check_return_
			virtual NtStatus NTAPI UnmapKnownDllSection64(_In_ DWORD64 MappedBase) = 0;

		private:
		/**
		 * @brief Internal implementation used by the cached GetProcAddress64 wrappers.
		 * @param[in] ModuleBase The 64-bit module base address.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		virtual NtResult<DWORD64> NTAPI GetProcAddress64Impl(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) = 0;

		VOID NTAPI MakeUTFStrImpl(_In_z_ PCWSTR Source, _Out_ PBYTE OutBuffer, _In_ SIZE_T PointerSize);
		VOID NTAPI MakeANSIStrImpl(_In_z_ PCSTR Source, _Out_ PBYTE OutBuffer, _In_ SIZE_T PointerSize);

		protected:
		ResolverBase() = default;

		std::unordered_map<std::string, DWORD64> _cache64;
		std::shared_mutex _mutex64;
	};
}
