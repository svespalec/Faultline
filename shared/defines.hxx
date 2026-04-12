#pragma once

// Defined via CMake for DLL targets, switches between dllexport/dllimport.
#ifdef FAULTLINE_EXPORT
  #define ANTICHEAT_API extern "C" __declspec(dllexport)
#else
  #define ANTICHEAT_API extern "C" __declspec(dllimport)
#endif
