add_library(sleepmask SHARED sleepmask.cpp)
target_include_directories(sleepmask PRIVATE ${CMAKE_SOURCE_DIR}/Include)
target_compile_definitions(sleepmask PRIVATE _USRDLL _WINDLL)
target_link_libraries(sleepmask PRIVATE ntdll advapi32)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(sleepmask PRIVATE -nostartfiles)
endif()
