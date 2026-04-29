#pragma once

#ifdef _WIN64
#include "x64/X64Resolver.hpp"
#endif 

#ifdef _M_IX86
#include "wow64/Wow64Resolver.hpp"
#endif

namespace NtExt {
    /**
     * @brief Namespace-style resolver facade.
     */
    namespace Resolver {
    }
}
