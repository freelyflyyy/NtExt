#include "NtCallExt.h"

#pragma warning(push)
#pragma warning(disable: 4251)

namespace NtExt {
    VOID NTAPI NtCallExt::_MakeUTFStrVa(LPCWSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize) {
        if ( !lpString || !outBuffer ) return;
        SIZE_T len = wcslen(lpString);

        *(USHORT*) (outBuffer) = (USHORT) len * sizeof(WCHAR);              // Length
        *(USHORT*) (outBuffer + 2) = (USHORT) (len + 1) * sizeof(WCHAR);    // MaxLength
        WCHAR* outStr;
        if ( pointerSize == 8 ) {
            outStr = (WCHAR*) (outBuffer + 16);
            *(DWORD64*) (outBuffer + 8) = (DWORD64) outStr;                 // Buffer
        } else if ( pointerSize == 4 ) {
            outStr = (WCHAR*) (outBuffer + 8);
            *(DWORD*) (outBuffer + 4) = (DWORD) (SIZE_T) outStr;            // Buffer 
        } else {
            return;
        }
        for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = lpString[ i ];
        outStr[ len ] = L'\0';
    }

    VOID NtCallExt::_MakeANSIStrVa(LPCSTR lpString, LPBYTE outBuffer, SIZE_T pointerSize) {
        if ( !lpString || !outBuffer ) return;
        SIZE_T len = strlen(lpString);

        *(USHORT*) (outBuffer) = (USHORT) len;                    // Length
        *(USHORT*) (outBuffer + 2) = (USHORT) (len + 1);          // MaxLength

        char* outStr;
        if ( pointerSize == 8 ) {
            outStr = (char*) (outBuffer + 16);
            *(DWORD64*) (outBuffer + 8) = (DWORD64) outStr;       // Buffer
        } else if ( pointerSize == 4 ) {
            outStr = (char*) (outBuffer + 8);
            *(DWORD*) (outBuffer + 4) = (DWORD) (SIZE_T) outStr;  // Buffer 
        } else {
            return;
        }

        for ( DWORD i = 0; i < len; i++ ) outStr[ i ] = lpString[ i ];
        outStr[ len ] = '\0';
    }
}
#pragma warning(pop)