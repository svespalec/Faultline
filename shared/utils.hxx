#pragma once

//
// Extract filename from a full path
// "C:\Windows\System32\ntdll.dll" -> "ntdll.dll"
//
inline std::string FilenameFromPath( const char* Path ) {
  std::string_view View( Path );

  auto Pos = View.find_last_of( "\\/" );

  if ( Pos != std::string_view::npos ) {
    View = View.substr( Pos + 1 );
  }

  return std::string( View );
}

//
// Get the module name for an address
//
inline std::string ModuleNameFromAddress( std::uintptr_t Address ) {
  HMODULE Module = nullptr;

  constexpr auto Flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                       | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;

  if ( !GetModuleHandleExA( Flags, reinterpret_cast<LPCSTR>( Address ), &Module ) ) {
    return {};
  }

  char Path[MAX_PATH]{};

  if ( !GetModuleFileNameA( Module, Path, MAX_PATH ) ) {
    return {};
  }

  return FilenameFromPath( Path );
}
