#include <shared/stdafx.hpp>

using StartFaultLineFn = void( * )();

int main() {
  auto Dll = LoadLibraryA( "anticheat.dll" );

  if ( !Dll ) {
    std::printf( "Failed to load anticheat.dll: %lu\n", GetLastError() );
    return 1;
  }

  auto Start = reinterpret_cast<StartFaultLineFn>( GetProcAddress( Dll, "StartFaultLine" ) );

  if ( !Start ) {
    std::printf( "Failed to find StartFaultLine export: %lu\n", GetLastError() );
    return 1;
  }

  Start();

  //
  // Keep the host alive while faultline runs.
  //
  std::getchar();

  return 0;
}
