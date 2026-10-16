add_library(counterplugin SHARED counterplugin.cpp)
target_include_directories(counterplugin PRIVATE ${CMAKE_SOURCE_DIR}/Include)
target_compile_definitions(counterplugin PRIVATE _USRDLL _WINDLL)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(counterplugin PRIVATE -nostartfiles)
endif()
