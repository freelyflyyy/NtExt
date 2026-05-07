set(NTEXT_PUBLIC_HEADERS
    "NtExt.hpp"
)

set(NTEXT_PCH_HEADERS
    "pch/stdafx.h"
)

set(NTEXT_INTERNAL_HEADERS
    "internal/NtStructs.h"
    "internal/ScopeAction.hpp"
    "internal/NtBase.hpp"
    "internal/NtStatus.hpp"
    "internal/NtResult.hpp"
)

set(NTEXT_INVOKER_BASE_HEADERS
    "invoker/InvokerBase.hpp"
    "invoker/NtExtInvokers.hpp"
)

set(NTEXT_INVOKER_WOW64_HEADERS
    "invoker/wow64/Wow64Invoker.hpp"
    "invoker/wow64/Wow64Call.hpp"
    "invoker/wow64/Wow64Syscall.hpp"
    "invoker/wow64/Wow64Anycall.hpp"
)

set(NTEXT_INVOKER_X64_HEADERS
    "invoker/x64/X64Invoker.hpp"
    "invoker/x64/X64Call.hpp"
    "invoker/x64/X64Syscall.hpp"
    "invoker/x64/X64Anycall.hpp"
)

set(NTEXT_RESOLVER_BASE_HEADERS
    "resolver/ResolverBase.hpp"
    "resolver/NtExtResolvers.hpp"
)

set(NTEXT_RESOLVER_BASE_SOURCES
    "resolver/ResolverBase.cpp"
)

set(NTEXT_RESOLVER_WOW64_HEADERS
    "resolver/wow64/Wow64Resolver.hpp"
)

set(NTEXT_RESOLVER_WOW64_SOURCES
    "resolver/wow64/Wow64Resolver.cpp"
)

set(NTEXT_RESOLVER_X64_HEADERS
    "resolver/x64/X64Resolver.hpp"
)

set(NTEXT_RESOLVER_X64_SOURCES
    "resolver/x64/X64Resolver.cpp"
)

set(NTEXT_INVOKER_HEADERS
    ${NTEXT_INVOKER_BASE_HEADERS}
    ${NTEXT_INVOKER_WOW64_HEADERS}
    ${NTEXT_INVOKER_X64_HEADERS}
)

set(NTEXT_RESOLVER_HEADERS
    ${NTEXT_RESOLVER_BASE_HEADERS}
    ${NTEXT_RESOLVER_WOW64_HEADERS}
    ${NTEXT_RESOLVER_X64_HEADERS}
)

set(NTEXT_RESOLVER_SOURCES
    ${NTEXT_RESOLVER_BASE_SOURCES}
    ${NTEXT_RESOLVER_WOW64_SOURCES}
    ${NTEXT_RESOLVER_X64_SOURCES}
)

set(NTEXT_HEADERS
    ${NTEXT_PUBLIC_HEADERS}
    ${NTEXT_PCH_HEADERS}
    ${NTEXT_INTERNAL_HEADERS}
    ${NTEXT_INVOKER_HEADERS}
    ${NTEXT_RESOLVER_HEADERS}
)

set(NTEXT_SOURCES
    ${NTEXT_RESOLVER_SOURCES}
)

source_group("Public" FILES ${NTEXT_PUBLIC_HEADERS})
source_group("PCH" FILES ${NTEXT_PCH_HEADERS})
source_group("Internal" FILES ${NTEXT_INTERNAL_HEADERS})
source_group("Invoker\\Base" FILES ${NTEXT_INVOKER_BASE_HEADERS})
source_group("Invoker\\WoW64" FILES ${NTEXT_INVOKER_WOW64_HEADERS})
source_group("Invoker\\x64" FILES ${NTEXT_INVOKER_X64_HEADERS})
source_group("Resolver\\Base" FILES ${NTEXT_RESOLVER_BASE_HEADERS} ${NTEXT_RESOLVER_BASE_SOURCES})
source_group("Resolver\\WoW64" FILES ${NTEXT_RESOLVER_WOW64_HEADERS} ${NTEXT_RESOLVER_WOW64_SOURCES})
source_group("Resolver\\x64" FILES ${NTEXT_RESOLVER_X64_HEADERS} ${NTEXT_RESOLVER_X64_SOURCES})

add_library(NtExt STATIC
    ${NTEXT_HEADERS}
    ${NTEXT_SOURCES}
)

target_precompile_headers(NtExt PRIVATE "pch/stdafx.h")

add_auto_refactor_headers(NtExt)

target_include_directories(NtExt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
