cmake_minimum_required (VERSION 3.16)
project(NtCallExt)

include("cmake_utils/auto_refactor_headers.cmake")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 如果支持，请为 MSVC 编译器启用热重载。
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

file(GLOB NTCALLEXT_HEADERS "src/*.h" "src/*.hpp")
file(GLOB NTCALLEXT_SOURCES "src/*.cpp")

add_library(NtCallExt STATIC 
    ${NTCALLEXT_HEADERS}
    ${NTCALLEXT_SOURCES}
)

target_precompile_headers(NtCallExt PRIVATE "src/stdafx.h")

target_include_directories(NtCallExt PUBLIC 
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

add_auto_refactor_headers(NtCallExt)

add_subdirectory(examples)