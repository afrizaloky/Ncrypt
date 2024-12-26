# CMakeList.txt : CMake project for GTest, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (GTest "GTest.cpp" "GTest.h")
target_link_libraries(GTest PRIVATE fmt::fmt GTest::gtest_main ncrypt kernel32    # Core Windows API functions
    user32      # GUI-related functions
    gdi32       # Graphics Device Interface
    ntdll       # NT API functions, & wntdll if you're referring to it
)

add_executable (LoadTest LoadTest.cpp)
target_link_libraries(LoadTest PRIVATE fmt::fmt GTest::gtest_main ncrypt kernel32    # Core Windows API functions
    user32      # GUI-related functions
    gdi32       # Graphics Device Interface
    ntdll       # NT API functions, & wntdll if you're referring to it
)
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET GTest PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
