#pragma once
#include "../ResolverBase.hpp"

namespace NtExt {

	#ifdef _M_IX86
	class Wow64Resolver : public ResolverBase {
		public:
		/**
		 * @brief Retrieves the singleton instance of the Wow64Resolver.
		 * @return A reference to the static Wow64Resolver instance.
		 */
		static Wow64Resolver& GetInstance() {
			static Wow64Resolver instance;
			return instance;
		}

		~Wow64Resolver() override = default;

		/**
		 * @brief Dynamically locates the 64-bit System Service Number (SSN) and syscall address.
		 * @param[in] ModuleBase The 64-bit base address of the module, for example ntdll.dll.
		 * @param[in] FunctionName The exported NTAPI function name.
		 * @return An NtResult containing the packed SSN and syscall address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetSyscallNumber64(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) override;

		/**
		 * @brief Retrieves the module entry from the 64-bit PEB loader list.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 64-bit LDR_DATA_TABLE_ENTRY address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetModuleLdrEntry64(_In_z_ PCWSTR ModuleName) override;

		/**
		 * @brief Retrieves the 64-bit base address of a loaded module from a Wow64 process.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 64-bit module base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetModuleBase64(_In_z_ PCWSTR ModuleName) override;

		/**
		 * @brief Gets the 64-bit Thread Environment Block (TEB) address.
		 * @return The 64-bit TEB address.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetTeb64() override;

		/**
		 * @brief Gets the 64-bit Process Environment Block (PEB) address.
		 * @return The 64-bit PEB address.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetPeb64() override;

		/**
		 * @brief Retrieves the 64-bit base address of ntdll.dll.
		 * @return An NtResult containing the 64-bit ntdll.dll base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetNtdll64() override;

		/**
		 * @brief Retrieves the 64-bit base address of kernel32.dll.
		 * @return An NtResult containing the 64-bit kernel32.dll base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetKernel64() override;

		/**
		 * @brief Manually loads a library into the 64-bit address space of the Wow64 process.
		 * @param[in] ModuleName The wide-character module name to load.
		 * @return An NtResult containing the 64-bit loaded module base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI LoadLibrary64(_In_z_ PCWSTR ModuleName) override;

		/**
		 * @brief Maps a 64-bit KnownDll section view.
		 * @param[in] DllName The KnownDll name to map.
		 * @param[out] MappedBase Receives the mapped 64-bit base address on success.
		 * @param[out] ViewSize Optional pointer that receives the mapped view size.
		 * @return NtStatus::Success on success; failure status otherwise.
		 */
		_Check_return_
			NtStatus NTAPI MapKnownDllSection64(_In_z_ PCWSTR DllName, _Out_ DWORD64* MappedBase, _Out_opt_ DWORD64* ViewSize = nullptr) override;

		/**
		 * @brief Unmaps a 64-bit KnownDll section view.
		 * @param[in] MappedBase The mapped 64-bit base address.
		 * @return NtStatus::Success on success; failure status otherwise.
		 */
		_Check_return_
			NtStatus NTAPI UnmapKnownDllSection64(_In_ DWORD64 MappedBase) override;

		/**
		 * @brief Retrieves the 64-bit address of LdrGetProcedureAddress.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetLdrGetProcedureAddress64();

		/**
		 * @brief Copies memory from a 64-bit source address into a 32-bit destination buffer.
		 * @param[out] Destination The destination buffer in the 32-bit address space.
		 * @param[in] Source The 64-bit source address.
		 * @param[in] Size The number of bytes to copy.
		 */
		VOID NTAPI memcpy64(_Out_writes_bytes_all_(Size) PVOID Destination, _In_ DWORD64 Source, _In_ SIZE_T Size);

		/**
		 * @brief Copies memory from a 32-bit source buffer into a 64-bit destination address.
		 * @param[in] Destination The 64-bit destination address.
		 * @param[in] Source The source buffer in the 32-bit address space.
		 * @param[in] Size The number of bytes to copy.
		 */
		VOID NTAPI memcpy64(_In_ DWORD64 Destination, _In_reads_bytes_(Size) PVOID Source, _In_ SIZE_T Size);

		/**
		 * @brief Retrieves the module entry from the 32-bit PEB loader list.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 32-bit LDR_DATA_TABLE_ENTRY address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI GetModuleLdrEntry32(_In_z_ PCWSTR ModuleName);

		/**
		 * @brief Retrieves the 32-bit base address of a loaded module.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 32-bit module base address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI GetModuleBase32(_In_z_ PCWSTR ModuleName);

		/**
		 * @brief Gets the 32-bit Thread Environment Block (TEB) address.
		 * @return The 32-bit TEB address.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD NTAPI GetTeb32();

		/**
		 * @brief Gets the 32-bit Process Environment Block (PEB) address.
		 * @return The 32-bit PEB address.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD NTAPI GetPeb32();

		/**
		 * @brief Retrieves the 32-bit base address of ntdll.dll.
		 * @return An NtResult containing the 32-bit ntdll.dll base address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI GetNtdll32();

		/**
		 * @brief Retrieves the 32-bit base address of kernel32.dll.
		 * @return An NtResult containing the 32-bit kernel32.dll base address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI GetKernel32();

		/**
		 * @brief Retrieves the 32-bit address of LdrGetProcedureAddress.
		 * @return An NtResult containing the 32-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI GetLdrGetProcedureAddress32();

		/**
		 * @brief Manually loads a library into the 32-bit address space.
		 * @param[in] ModuleName The wide-character module name to load.
		 * @return An NtResult containing the 32-bit loaded module base address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI LoadLibrary32(_In_z_ PCWSTR ModuleName);

		/**
		 * @brief Maps a 32-bit KnownDll section view.
		 * @param[in] DllName The KnownDll name to map.
		 * @param[out] MappedBase Receives the mapped 32-bit base address on success.
		 * @param[out] ViewSize Optional pointer that receives the mapped view size.
		 * @return NtStatus::Success on success; failure status otherwise.
		 */
		_Check_return_
			NtStatus NTAPI MapKnownDllSection32(_In_z_ PCWSTR DllName, _Out_ DWORD* MappedBase, _Out_opt_ PSIZE_T ViewSize = nullptr);

		/**
		 * @brief Unmaps a 32-bit KnownDll section view.
		 * @param[in] MappedBase The mapped 32-bit base address.
		 * @return NtStatus::Success on success; failure status otherwise.
		 */
		_Check_return_
			NtStatus NTAPI UnmapKnownDllSection32(_In_opt_ DWORD MappedBase);

		/**
		 * @brief Thread-safely checks whether a 32-bit exported function address is cached.
		 * @param[in] FunctionName The exported function name.
		 * @param[out] Address Receives the cached 32-bit address when the function returns TRUE.
		 * @return TRUE when a cached address was found; otherwise FALSE.
		 */
		_Check_return_ _Success_(return != FALSE)
			BOOL IsCached32(_In_ const std::string& FunctionName, _Out_ DWORD* Address) {
			if ( !Address ) {
				return FALSE;
			}
			*Address = 0;
			std::shared_lock<std::shared_mutex> lock(_mutex32);
			auto it = _cache32.find(FunctionName);
			if ( it == _cache32.end() || !it->second ) {
				return FALSE;
			}
			*Address = it->second;
			return TRUE;
		}

		/**
		 * @brief Retrieves the 32-bit address of an exported function and caches successful lookups.
		 * @param[in] ModuleBase The 32-bit module base address.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 32-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD> GetProcAddress32(_In_ DWORD ModuleBase, _In_ const std::string& FunctionName) {
			DWORD cachedAddr = 0;
			if ( IsCached32(FunctionName, &cachedAddr) ) {
				return NtResult<DWORD>::Success(cachedAddr);
			}
			if ( !ModuleBase ) {
				return NtResult<DWORD>::Failure(STATUS_INVALID_PARAMETER, L"Invalid module base.");
			}

			auto procAddr = GetProcAddress32Impl(ModuleBase, FunctionName.c_str());
			if ( procAddr ) {
				std::unique_lock<std::shared_mutex> lock(_mutex32);
				_cache32[ FunctionName ] = procAddr.Value();
			}
			return procAddr;
		}

		/**
		 * @brief Retrieves the 32-bit address of an exported function by module name.
		 * @param[in] ModuleName The wide-character module name.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 32-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD> GetProcAddress32(_In_ const std::wstring& ModuleName, _In_ const std::string& FunctionName) {
			DWORD cachedAddr = 0;
			if ( IsCached32(FunctionName, &cachedAddr) ) {
				return NtResult<DWORD>::Success(cachedAddr);
			}

			auto moduleBase = GetModuleBase32(ModuleName.c_str());
			if ( !moduleBase && moduleBase.Code() == STATUS_DLL_NOT_FOUND ) {
				moduleBase = LoadLibrary32(ModuleName.c_str());
			}
			if ( !moduleBase ) {
				return NtResult<DWORD>::Failure(moduleBase);
			}
			return GetProcAddress32(moduleBase.Value(), FunctionName);
		}

		/**
		 * @brief Retrieves the 32-bit address of an exported function from the 32-bit ntdll.dll.
		 * @param[in] FunctionName The exported function name expected in ntdll.dll.
		 * @return An NtResult containing the 32-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD> GetProcAddress32(_In_ const std::string& FunctionName) {
			auto ntdll32 = GetNtdll32();
			if ( !ntdll32 ) {
				return NtResult<DWORD>::Failure(ntdll32);
			}
			return GetProcAddress32(ntdll32.Value(), FunctionName);
		}

		protected:
		/**
		 * @brief Internal implementation used by the cached 64-bit GetProcAddress64 wrappers.
		 * @param[in] ModuleBase The 64-bit module base address.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetProcAddress64Impl(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) override;

		/**
		 * @brief Internal implementation used by the cached 32-bit GetProcAddress32 wrappers.
		 * @param[in] ModuleBase The 32-bit module base address.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 32-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD> NTAPI GetProcAddress32Impl(_In_ DWORD ModuleBase, _In_z_ PCSTR FunctionName);

		private:
		Wow64Resolver() = default;

		std::unordered_map<std::string, DWORD> _cache32;
		std::shared_mutex _mutex32;
	};
	#endif
}
