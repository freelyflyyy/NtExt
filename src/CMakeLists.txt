set(HEADER_MAIN "NtExt.hpp")

set(HEADER_INTERNAL 
    "internal/NtApi.h"
)
source_group("Internal" FILES ${HEADER_INTERNAL})

set(HEADER_INVOKER
    "invoker/InvokerBase.hpp"
    "invoker/wow64/Wow64Invoker.hpp"
    "invoker/wow64/Wow64Call.hpp"
    "invoker/wow64/Wow64Syscall.hpp"
    "invoker/wow64/Wow64Anycall.hpp"
    "invoker/x64/X64Invoker.hpp"
    "invoker/x64/X64Call.hpp"
    "invoker/x64/X64Syscall.hpp"
    "invoker/x64/X64Anycall.hpp"
    "invoker/NtExtInvokers.hpp"
)

source_group("Invoker" FILES ${HEADER_INVOKER})

set(HEADER_RESOLVER 
    "resolver/ResolverBase.hpp"
    "resolver/wow64/Wow64Resolver.hpp"
    "resolver/x64/X64Resolver.hpp"
    "resolver/NtExtResolvers.hpp"
)

set(SOURCE_RESOLVER
    "resolver/ResolverBase.cpp"
    "resolver/wow64/Wow64Resolver.cpp"
    "resolver/x64/X64Resolver.cpp"
)
source_group("Resolver" FILES ${HEADER_RESOLVER})

set(HEADER_PCH 
    "pch/stdafx.h"
)
source_group("PCH" FILES ${HEADER_PCH})

set(ALL_HEADERS 
    ${HEADER_INTERNAL} 
    ${HEADER_INVOKER} 
    ${HEADER_RESOLVER}
    ${HEADER_PCH}
    ${HEADER_MAIN}
)

set(ALL_SOURCES 
    ${SOURCE_RESOLVER}
)

add_library(NtExt STATIC 
    ${ALL_HEADERS} 
    ${ALL_SOURCES}
)

target_precompile_headers(NtExt PRIVATE "pch/stdafx.h")

add_auto_refactor_headers(NtExt)

target_include_directories(NtExt PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)