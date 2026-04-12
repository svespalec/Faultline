#include "stack_walk.hxx"
#include <shared/safe_handle.hxx>
#include <shared/utils.hxx>

constexpr std::size_t MaxFrames = 64;

std::vector<StackFrame> CaptureStack( std::uintptr_t ThreadId ) {
  std::vector<StackFrame> Frames{};

  //
  // Open the target thread for stack inspection.
  //
  constexpr auto Access = THREAD_SUSPEND_RESUME
                        | THREAD_GET_CONTEXT
                        | THREAD_QUERY_INFORMATION;

  SafeHandle Thread( OpenThread( Access, FALSE, static_cast<DWORD>( ThreadId ) ) );

  if ( !Thread ) {
    return Frames;
  }

  //
  // Freeze the thread so we can safely read its context.
  //
  if ( SuspendThread( Thread ) == static_cast<DWORD>( -1 ) ) {
    return Frames;
  }

  CONTEXT Ctx{};
  Ctx.ContextFlags = CONTEXT_FULL;

  if ( !GetThreadContext( Thread, &Ctx ) ) {
    ResumeThread( Thread );
    return Frames;
  }

  //
  // Set up the initial stack frame from the thread's registers
  //
  STACKFRAME64 Sf{};

  Sf.AddrPC.Offset    = Ctx.Rip;
  Sf.AddrPC.Mode      = AddrModeFlat;
  Sf.AddrFrame.Offset = Ctx.Rbp;
  Sf.AddrFrame.Mode   = AddrModeFlat;
  Sf.AddrStack.Offset = Ctx.Rsp;
  Sf.AddrStack.Mode   = AddrModeFlat;

  auto Process = GetCurrentProcess();

  Frames.reserve( MaxFrames );

  //
  // Walk the call stack frame by frame
  //
  for ( std::size_t I = 0; I < MaxFrames; ++I ) {
    if ( !StackWalk64(
      IMAGE_FILE_MACHINE_AMD64,
      Process,
      Thread,
      &Sf, &Ctx, nullptr,
      SymFunctionTableAccess64,
      SymGetModuleBase64,
      nullptr ) ) {
      break;
    }

    if ( Sf.AddrPC.Offset == 0 ) {
      break;
    }

    auto Pc = static_cast<std::uintptr_t>( Sf.AddrPC.Offset );

    Frames.push_back( {
      .Pc            = Pc,
      .InValidModule = false,
      .ModuleName    = ModuleNameFromAddress( Pc ),
    } );
  }

  ResumeThread( Thread );

  return Frames;
}
