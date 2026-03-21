set(HEADER_CORE 
    "NtCallExt.h"
    "Wow64NtCallExt.h"
    "X64NtCallExt.h"
)
set(SOURCE_CORE 
    "NtCallExt.cpp"
    "Wow64NtCallExt.cpp"
    "X64NtCallExt.cpp"
)
source_group("Core" FILES ${HEADER_CORE} ${SOURCE_CORE})


set(HEADER_INTERNAL 
    "internal/NtApi.h"
    "internal/NtAsm.h"
)
source_group("Internal" FILES ${HEADER_INTERNAL})

set(HEADER_INVOKER
    "invoker/InvokerBase.hpp"
    "invoker/wow64/Wow64Invoker.hpp"
    "invoker/wow64/Wow64Call.hpp"
    "invoker/wow64/Wow64Syscall.hpp"
    "invoker/x64/X64Invoker.hpp"
    "invoker/x64/X64Call.hpp"
    "invoker/x64/X64Syscall.hpp"
    "invoker/NtExtInvokers.hpp"
)

source_group("Invoker" FILES ${HEADER_INVOKER})

set(HEADER_PCH 
    "pch/stdafx.h"
)
source_group("PCH" FILES ${HEADER_PCH})

set(ALL_HEADERS 
    ${HEADER_CORE} 
    ${HEADER_INTERNAL} 
    ${HEADER_INVOKER} 
    ${HEADER_PCH}
)

set(ALL_SOURCES 
    ${SOURCE_CORE}
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