add_library( anticheat SHARED
  main.cpp
)

target_link_libraries( anticheat PRIVATE shared )
target_include_directories( anticheat PRIVATE ${CMAKE_SOURCE_DIR} )
target_precompile_headers( anticheat PRIVATE ${CMAKE_SOURCE_DIR}/shared/stdafx.hpp )
target_compile_options( anticheat PRIVATE /W4 /WX )
