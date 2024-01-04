cmake_minimum_required(VERSION 3.13.4)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(run-exe-via-impersonating LANGUAGES CXX)

if(COMMAND cmake_policy)
cmake_policy(SET CMP0003 NEW)
cmake_policy(SET CMP0005 NEW)
endif(COMMAND cmake_policy)

# add definitions for project name and version
# they can be reached from the source codes
add_definitions(-DPROJECT_NAME="${PROJECT_NAME}")
add_definitions(-DPROJECT_VER="${PROJECT_VERSION}")

# set OS based properties
if (WIN32)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    if(MSVC)
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    endif(MSVC)
elseif(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
else()
    message(FATAL_ERROR "Operating system type couldn't found!")
endif ()

add_subdirectory(external)
add_subdirectory(lib)
add_subdirectory(src)