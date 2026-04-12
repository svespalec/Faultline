#include "faultline.hxx"

void Faultline::Start() {
  //
  // Check if we're already running.
  //
  if ( MonitorThread ) {
    return;
  }

  //
  // Set up symbolic context engine.
  //
  SymSetOptions( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS );
  SymInitialize( GetCurrentProcess(), nullptr, TRUE );

  MonitorThread.Handle = CreateThread( nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr );

  if ( !MonitorThread ) {
    LOG_ERROR( "Failed to create monitor thread: {}", GetLastError() );
    return;
  }

  LOG_OK( "Faultline started" );
}

void Faultline::Stop() {
  if ( MonitorThread ) {
    WaitForSingleObject( MonitorThread, 2000 );
  }

  SymCleanup( GetCurrentProcess() );

  LOG_INFO( "Faultline stopped" );
}

DWORD WINAPI Faultline::MonitorThreadProc( LPVOID ) {
  LOG_STEP( "Monitor thread running" );

  return 0;
}
