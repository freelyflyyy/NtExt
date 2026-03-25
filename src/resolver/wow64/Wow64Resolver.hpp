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
         * @brief Get the Nt function ssn and syscall commend addr.
         * @param[in] hMod The 64-bit base address of the module (e.g., ntdll).
         * @param[in] funcName The name of the NTAPI function.
         * @return A DWORD64 value where the high 16 bits represent the SSN, and the low 48 bits represent the syscall address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

        /**
         * @brief Get the module node in the 64-bit PEB LDR.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 64-bit memory address of the module's LDR_DATA_TABLE_ENTRY.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) override;

        /**
         * @brief Get the 64-bit module base address.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 64-bit base address of the module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) override;

        /**
         * @brief Get the 64-bit TEB (Thread Environment Block) address of the current process.
         * @return The 64-bit TEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetTeb64() override;

        /**
         * @brief Get the 64-bit PEB (Process Environment Block) address of the current process.
         * @return The 64-bit PEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetPeb64() override;

        /**
         * @brief Get the 64-bit ntdll.dll base address.
         * @return The 64-bit module base address of ntdll.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetNtdll64() override;

        /**
         * @brief Get the 64-bit kernel32.dll base address.
         * @return The 64-bit module base address of kernel32.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetKernel64() override;

        /**
         * @brief Manually loads a library into the 64-bit address space of the Wow64 process.
         * @param[in] moduleName The wide-character name of the module to load.
         * @return The 64-bit base address of the loaded module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) override;

        /**
         * @brief Retrieves the 64-bit address of the LdrGetProcedureAddress function.
         * @return The 64-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetLdrGetProcedureAddress64();

        /**
         * @brief Copies memory from a 64-bit source address to a 32-bit destination buffer using a shellcode stub.
         * @param[out] dest The destination buffer in the 32-bit address space.
         * @param[in] src The 64-bit source address to copy from.
         * @param[in] sz The number of bytes to copy.
         */
        VOID NTAPI memcpy64(_Out_writes_bytes_all_(sz) VOID* dest, _In_ DWORD64 src, _In_ SIZE_T sz);

        /**
         * @brief Copies memory from a 32-bit source buffer to a 64-bit destination address using a shellcode stub.
         * @param[in] dest The 64-bit destination address to copy to.
         * @param[in] src The source buffer in the 32-bit address space.
         * @param[in] sz The number of bytes to copy.
         */
        VOID NTAPI memcpy64(_In_ DWORD64 dest, _In_reads_bytes_(sz) VOID* src, _In_ SIZE_T sz);

        /**
         * @brief Retrieves the 32-bit base memory address of a loaded module.
         * @param[in] moduleName The wide-character name of the module.
         * @return The 32-bit base address of the module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetModuleBase32(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Gets the 32-bit address of the Thread Environment Block (TEB).
         * @return The 32-bit TEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetTeb32();

        /**
         * @brief Gets the 32-bit address of the Process Environment Block (PEB).
         * @return The 32-bit PEB address.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetPeb32();

        /**
         * @brief Retrieves the 32-bit base address of ntdll.dll.
         * @return The 32-bit base address of ntdll.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetNtdll32();

        /**
         * @brief Retrieves the 32-bit base address of kernel32.dll.
         * @return The 32-bit base address of kernel32.dll.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetKernel32();

        /**
         * @brief Retrieves the 32-bit address of the LdrGetProcedureAddress function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetLdrGetProcedureAddress32();

        /**
         * @brief Manually loads a library into the 32-bit address space.
         * @param[in] moduleName The wide-character name of the module to load.
         * @return The 32-bit base address of the loaded module.
         */
        _Check_return_ _Success_(return != 0)
            DWORD NTAPI LoadLibrary32(_In_z_ const wchar_t* moduleName);

        /**
         * @brief Thread-safely checks if a 32-bit function's memory address is already cached.
         * @param[in] funcName The name of the target function.
         * @return The cached 32-bit address if found, otherwise 0.
         */
        _Success_(return != 0)
            DWORD IsCached32(_In_ const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex32);
            auto it = _cache32.find(funcName);
            if ( it != _cache32.end() ) return it->second;
            return 0;
        }

        /**
         * @brief Retrieves the 32-bit memory address of an exported function, using an internal cache to optimize repeated calls.
         * @param[in] hMod The 32-bit base address of the module containing the function.
         * @param[in] funcName The name of the exported function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ DWORD hMod, _In_ const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD procAddr = GetProcAddressImpl(hMod, funcName.c_str());
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex32);
                _cache32[ funcName ] = procAddr;
            }
            return procAddr;
        }

        /**
         * @brief Retrieves the 32-bit memory address of an exported function by providing the module name.
         * @param[in] moduleName The wide-character name of the target module.
         * @param[in] funcName The name of the exported function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ const std::wstring& moduleName, _In_ const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            DWORD hMod = GetModuleBase32(moduleName.c_str());
            if ( hMod == 0 ) hMod = LoadLibrary32(moduleName.c_str());
            if ( hMod == 0 ) return 0;
            return GetProcAddress32(hMod, funcName);
        }

        /**
         * @brief Retrieves the 32-bit memory address of an exported function, defaulting to searching within the 32-bit ntdll.dll.
         * @param[in] funcName The name of the exported function.
         * @return The 32-bit address of the function.
         */
        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            return GetProcAddress32(GetNtdll32(), funcName);
        }

        protected:
        /**
         * @brief Internal implementation to resolve exported 64-bit function addresses via Heaven's Gate.
         * @param[in] hMod The 64-bit module base address.
         * @param[in] funcName The function name.
         * @return The 64-bit function address.
         */
        DWORD64 NTAPI GetProcAddress64Impl(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

        /**
         * @brief Internal implementation to resolve exported 32-bit function addresses.
         * @param[in] hMod The 32-bit module base address.
         * @param[in] funcName The function name.
         * @return The 32-bit function address.
         */
        DWORD NTAPI GetProcAddressImpl(_In_ DWORD hMod, _In_z_ const char* funcName);

        private:
        Wow64Resolver() = default;

        std::unordered_map<std::string, DWORD> _cache32;
        std::shared_mutex _mutex32;
    };
    #endif
}