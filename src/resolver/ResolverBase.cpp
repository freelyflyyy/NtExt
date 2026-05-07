#include "ResolverBase.hpp"
#pragma warning(push)
#pragma warning(disable: 4251)

namespace NtExt {
    VOID NTAPI ResolverBase::MakeUTFStrImpl(_In_z_ PCWSTR Source, _Out_ PBYTE OutBuffer, _In_ SIZE_T PointerSize) {
        if ( !Source || !OutBuffer ) {
            return;
        }
        SIZE_T len = wcslen(Source);
        *(USHORT*) (OutBuffer) = (USHORT) len * sizeof(WCHAR);
        *(USHORT*) (OutBuffer + 2) = (USHORT) (len + 1) * sizeof(WCHAR);
        WCHAR* outStr;
        if ( PointerSize == 8 ) {
            outStr = (WCHAR*) (OutBuffer + 16);
            *(DWORD64*) (OutBuffer + 8) = (DWORD64) outStr;
        } else if ( PointerSize == 4 ) {
            outStr = (WCHAR*) (OutBuffer + 8);
            *(DWORD*) (OutBuffer + 4) = (DWORD) (SIZE_T) outStr;
        } else { return; }
        for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = Source[ i ];
        outStr[ len ] = L'\0';
    }

    VOID NTAPI ResolverBase::MakeANSIStrImpl(_In_z_ PCSTR Source, _Out_ PBYTE OutBuffer, _In_ SIZE_T PointerSize) {
        if ( !Source || !OutBuffer ) {
            return;
        }
        SIZE_T len = strlen(Source);
        *(USHORT*) (OutBuffer) = (USHORT) len;
        *(USHORT*) (OutBuffer + 2) = (USHORT) (len + 1);
        char* outStr;
        if ( PointerSize == 8 ) {
            outStr = (char*) (OutBuffer + 16);
            *(DWORD64*) (OutBuffer + 8) = (DWORD64) outStr;
        } else if ( PointerSize == 4 ) {
            outStr = (char*) (OutBuffer + 8);
            *(DWORD*) (OutBuffer + 4) = (DWORD) (SIZE_T) outStr;
        } else { return; }
        for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = Source[ i ];
        outStr[ len ] = '\0';
    }
}
#pragma warning(pop)
