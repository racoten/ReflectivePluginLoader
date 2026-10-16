add_library(cmdplugin SHARED cmdplugin.cpp)
target_include_directories(cmdplugin PRIVATE ${CMAKE_SOURCE_DIR}/Include)
target_compile_definitions(cmdplugin PRIVATE _USRDLL _WINDLL)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(cmdplugin PRIVATE -nostartfiles)
endif()
