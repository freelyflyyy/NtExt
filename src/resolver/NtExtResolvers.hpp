#pragma once

#ifdef _WIN64
#include "x64/X64Resolver.hpp"
#endif 

#ifdef _M_IX86
#include "wow64/Wow64Resolver.hpp"
#endif

namespace NtExt {
    #ifdef _WIN64
    inline X64Resolver& Resolver = X64Resolver::GetInstance();
    #endif

    #ifdef _M_IX86
    inline Wow64Resolver& Resolver = Wow64Resolver::GetInstance();
    #endif
}