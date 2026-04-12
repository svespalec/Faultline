add_executable( injector main.cxx )

target_link_libraries( injector PRIVATE shared )
target_precompile_headers( injector PRIVATE ${CMAKE_SOURCE_DIR}/shared/stdafx.hxx )
target_compile_options( injector PRIVATE /W4 /WX )
