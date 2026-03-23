#pragma once
#include "../ResolverBase.hpp"

namespace NtExt {

    #ifdef _M_IX86
    class Wow64Resolver : public ResolverBase {
        public:
        static Wow64Resolver& GetInstance() {
            static Wow64Resolver instance;
            return instance;
        }

        ~Wow64Resolver() = default;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetSyscallNumber64(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetModuleLdrEntry64(_In_z_ const wchar_t* moduleName) override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetModuleBase64(_In_z_ const wchar_t* moduleName) override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetTeb64() override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetPeb64() override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetNtdll64() override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetKernel64() override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI LoadLibrary64(_In_z_ const wchar_t* moduleName) override;

        _Check_return_ _Success_(return != 0)
            DWORD64 NTAPI GetLdrGetProcedureAddress64();

        VOID NTAPI memcpy64(_Out_writes_bytes_all_(sz) VOID* dest, _In_ DWORD64 src, _In_ SIZE_T sz);

        VOID NTAPI memcpy64(_In_ DWORD64 dest, _In_reads_bytes_(sz) VOID* src, _In_ SIZE_T sz);

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetModuleBase32(_In_z_ const wchar_t* moduleName);

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetTeb32();

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetPeb32();

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetNtdll32();

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetKernel32();

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI GetLdrGetProcedureAddress32();

        _Check_return_ _Success_(return != 0)
            DWORD NTAPI LoadLibrary32(_In_z_ const wchar_t* moduleName);

        _Success_(return != 0)
            DWORD IsCached32(_In_ const std::string& funcName) {
            std::shared_lock<std::shared_mutex> lock(_mutex32);
            auto it = _cache32.find(funcName);
            if ( it != _cache32.end() ) return it->second;
            return 0;
        }

        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ DWORD hMod, _In_ const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            if ( hMod == 0 ) return 0;
            DWORD procAddr = _GetProcAddress32(hMod, funcName.c_str());
            if ( procAddr ) {
                std::unique_lock<std::shared_mutex> lock(_mutex32);
                _cache32[ funcName ] = procAddr;
            }
            return procAddr;
        }

        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ const std::wstring& moduleName, _In_ const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            DWORD hMod = GetModuleBase32(moduleName.c_str());
            if ( hMod == 0 ) hMod = LoadLibrary32(moduleName.c_str());
            if ( hMod == 0 ) return 0;
            return GetProcAddress32(hMod, funcName);
        }

        _Check_return_ _Success_(return != 0)
            DWORD GetProcAddress32(_In_ const std::string& funcName) {
            if ( auto addr = IsCached32(funcName) ) return addr;
            return GetProcAddress32(GetNtdll32(), funcName);
        }

        protected:
        DWORD64 NTAPI _GetProcAddress64(_In_ DWORD64 hMod, _In_z_ const char* funcName) override;
        DWORD NTAPI _GetProcAddress32(_In_ DWORD hMod, _In_z_ const char* funcName);

        private:
        Wow64Resolver() = default;

        std::unordered_map<std::string, DWORD> _cache32;
        std::shared_mutex _mutex32;
    };
    #endif
}