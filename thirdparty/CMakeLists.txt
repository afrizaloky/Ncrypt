execute_process(
    COMMAND git submodule update --init --recursive --recommend-shallow
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    ECHO_OUTPUT_VARIABLE
    ECHO_ERROR_VARIABLE
    COMMAND_ERROR_IS_FATAL ANY
)

#===============================================================================
# vcpkg
#===============================================================================

if(CMAKE_GENERATOR_PLATFORM EQUAL "x64")

    set(VCPKG_TARGET_TRIPLET "x64-windows-static")
    set(ENV{VCPKG_DEFAULT_TRIPLET} "x64-windows-static")
    set(ENV{VCPKG_DEFAULT_HOST_TRIPLET} "x64-windows-static")
    # Add x64 specific configurations
else()
    set(VCPKG_TARGET_TRIPLET "x86-windows-static")
    set(ENV{VCPKG_DEFAULT_TRIPLET} "x86-windows-static")
    set(ENV{VCPKG_DEFAULT_HOST_TRIPLET} "x86-windows-static")
    # Add x86 specific configurations
endif()
# Include VCPKG toolchain file
include("${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")

find_package(GTest REQUIRED GLOBAL)
find_package(fmt REQUIRED GLOBAL)