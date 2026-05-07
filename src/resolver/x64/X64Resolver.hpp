#pragma once
#include "../ResolverBase.hpp"

namespace NtExt {
	#ifdef _WIN64
	class X64Resolver : public ResolverBase {
		public:
		/**
		 * @brief Retrieves the singleton instance of the X64Resolver.
		 * @return A reference to the static X64Resolver instance.
		 */
		static X64Resolver& GetInstance() {
			static X64Resolver instance;
			return instance;
		}

		~X64Resolver() override = default;

		/**
		 * @brief Dynamically locates the System Service Number (SSN) and syscall address in a native 64-bit process.
		 * @param[in] ModuleBase The 64-bit base address of the module, for example ntdll.dll.
		 * @param[in] FunctionName The exported NTAPI function name.
		 * @return An NtResult containing the packed SSN and syscall address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetSyscallNumber64(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) override;

		/**
		 * @brief Traverses the native 64-bit PEB to find a module LDR_DATA_TABLE_ENTRY.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 64-bit LDR entry address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetModuleLdrEntry64(_In_z_ PCWSTR ModuleName) override;

		/**
		 * @brief Retrieves the native 64-bit base address of a loaded module.
		 * @param[in] ModuleName The wide-character module name.
		 * @return An NtResult containing the 64-bit module base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetModuleBase64(_In_z_ PCWSTR ModuleName) override;

		/**
		 * @brief Gets the native 64-bit Thread Environment Block (TEB) address.
		 * @return The 64-bit TEB address.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetTeb64() override;

		/**
		 * @brief Gets the native 64-bit Process Environment Block (PEB) address.
		 * @return The 64-bit PEB address.
		 */
		_Check_return_ _Success_(return != 0)
			DWORD64 NTAPI GetPeb64() override;

		/**
		 * @brief Retrieves the native 64-bit base address of ntdll.dll.
		 * @return An NtResult containing the 64-bit ntdll.dll base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetNtdll64() override;

		/**
		 * @brief Retrieves the native 64-bit base address of kernel32.dll.
		 * @return An NtResult containing the 64-bit kernel32.dll base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetKernel64() override;

		/**
		 * @brief Manually loads a library into the native 64-bit address space.
		 * @param[in] ModuleName The wide-character module name to load.
		 * @return An NtResult containing the 64-bit loaded module base address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI LoadLibrary64(_In_z_ PCWSTR ModuleName) override;

		/**
		 * @brief Maps a KnownDll section into the current process as a 64-bit view.
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

		protected:
		/**
		 * @brief Internal implementation used by the cached GetProcAddress64 wrappers.
		 * @param[in] ModuleBase The 64-bit module base address.
		 * @param[in] FunctionName The exported function name.
		 * @return An NtResult containing the 64-bit function address on success.
		 */
		_Check_return_
			NtResult<DWORD64> NTAPI GetProcAddress64Impl(_In_ DWORD64 ModuleBase, _In_z_ PCSTR FunctionName) override;

		private:
		X64Resolver() = default;
	};
	#endif
}
