cmake_minimum_required( VERSION 4.1 )
project( faultline LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 23 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )

add_subdirectory( shared )
add_subdirectory( anticheat )
add_subdirectory( host )
add_subdirectory( injector )
add_subdirectory( payload )
