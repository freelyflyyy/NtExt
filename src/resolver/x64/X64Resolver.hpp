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
        * @brief Dynamically locates the System Service Number (SSN) for a given NTAPI function in a native 64-bit process.
        * @param[in] hMod The 64-bit base address of the module (e.g., ntdll.dll).
        * @param[in] funcName The name of the NTAPI function.
        * @return A 64-bit value where the high 16 bits contain the SSN, and the low 48 bits contain the syscall address.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

       /**
        * @brief Traverses the native 64-bit PEB to find the LDR_DATA_TABLE_ENTRY for a specific module.
        * @param[in] moduleName The wide-character name of the module.
        * @return The 64-bit memory address of the module's LDR entry.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) override;

       /**
        * @brief Retrieves the native 64-bit base address of a loaded module.
        * @param[in] moduleName The wide-character name of the module.
        * @return The 64-bit base address of the module.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) override;

       /**
        * @brief Gets the native 64-bit Thread Environment Block (TEB) address.
        * @details In a native x64 environment, this is typically read directly from the GS segment register (gs:[0x30]).
        * @return The 64-bit TEB address.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetTeb64() override;

       /**
        * @brief Gets the native 64-bit Process Environment Block (PEB) address.
        * @details In a native x64 environment, this is typically read directly from the GS segment register (gs:[0x60]).
        * @return The 64-bit PEB address.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetPeb64() override;

       /**
        * @brief Retrieves the base address of the native 64-bit ntdll.dll.
        * @return The 64-bit module base address of ntdll.dll.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetNtdll64() override;

       /**
        * @brief Retrieves the base address of the native 64-bit kernel32.dll.
        * @return The 64-bit module base address of kernel32.dll.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetKernel64() override;

       /**
        * @brief Manually loads a library into the native 64-bit address space.
        * @param[in] moduleName The wide-character name of the module to load.
        * @return The 64-bit base address of the loaded module.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) override;

       protected:
       /**
        * @brief Internal implementation to resolve exported function addresses in a native 64-bit environment.
        * @param[in] hMod The 64-bit module base address.
        * @param[in] funcName The function name.
        * @return The 64-bit function address.
        */
       _Check_return_ _Success_(return != 0)
          DWORD64 NTAPI GetProcAddress64Impl(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

       private:
       X64Resolver() = default;
    };
    #endif
}