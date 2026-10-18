add_executable(harness main.cpp)
target_include_directories(harness PRIVATE ${CMAKE_SOURCE_DIR}/Include)

add_executable(controller controller.cpp)
target_include_directories(controller PRIVATE ${CMAKE_SOURCE_DIR}/Include)

add_executable(beacon beacon.cpp)
target_include_directories(beacon PRIVATE ${CMAKE_SOURCE_DIR}/Include)
