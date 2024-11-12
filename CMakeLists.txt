# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("GTest")

if(CMAKE_BUILD_TYPE MATCHES Debug)
    # Use the Debug runtime library (MDd or MTd)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")  # Static Debug
else()
    # Use the Release runtime library (MD or MT)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")  # Static Release
endif()

if(CMAKE_GENERATOR_PLATFORM EQUAL "x64")
    message(STATUS "Configuring for x64 (64-bit)")
    # Add x64 specific configurations
else()
    message(STATUS "Configuring for x86 (32-bit)")
    # Add x86 specific configurations
endif()
add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

# Requirements
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


include_directories(Include)

add_subdirectory(thirdparty)

# Include sub-projects.
add_subdirectory ("GTest")
