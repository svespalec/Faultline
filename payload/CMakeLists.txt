add_library( payload SHARED main.cxx )

target_link_libraries( payload PRIVATE shared )
target_include_directories( payload PRIVATE ${CMAKE_SOURCE_DIR} )
target_precompile_headers( payload PRIVATE ${CMAKE_SOURCE_DIR}/shared/stdafx.hxx )
target_compile_definitions( payload PRIVATE FAULTLINE_EXPORT )
target_compile_options( payload PRIVATE /W4 /WX )
