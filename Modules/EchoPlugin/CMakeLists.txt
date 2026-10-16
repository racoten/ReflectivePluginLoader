add_library(echoplugin SHARED echoplugin.cpp)
target_include_directories(echoplugin PRIVATE ${CMAKE_SOURCE_DIR}/Include)
target_compile_definitions(echoplugin PRIVATE _USRDLL _WINDLL)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(echoplugin PRIVATE -nostartfiles)
endif()
