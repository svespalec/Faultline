#pragma once

#include <dbghelp.h>

#pragma comment( lib, "dbghelp.lib" )
#pragma comment( lib, "psapi.lib" )

struct StackFrame {
  std::uintptr_t Pc{};
  bool KnownModule{};
  std::string ModuleName{};
};

[[nodiscard]] std::vector<StackFrame> CaptureStack( std::uintptr_t ThreadId );
