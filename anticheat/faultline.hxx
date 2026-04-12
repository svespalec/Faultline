#pragma once

#include "stack_walk.hxx"

class Faultline {
public:
  void Start();
  void Stop();

private:
  static DWORD WINAPI MonitorThreadProc( LPVOID Param );

  SafeHandle MonitorThread;
};
