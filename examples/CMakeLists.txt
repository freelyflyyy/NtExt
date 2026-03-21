project(Example)

add_executable(Example main.cpp)

target_link_libraries(Example PRIVATE NtExt)