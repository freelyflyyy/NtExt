#include "ResolverBase.hpp"
#pragma warning(push)
#pragma warning(disable: 4251)

namespace NtExt {
    VOID NTAPI ResolverBase::MakeUTFStrImpl(_In_z_ LPCWSTR lpString, _Out_ LPBYTE outBuffer, _In_ SIZE_T pointerSize) {
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

    VOID NTAPI ResolverBase::MakeANSIStrImpl(_In_z_ LPCSTR lpString, _Out_ LPBYTE outBuffer, _In_ SIZE_T pointerSize) {
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
#pragma warning(pop)