#pragma once

struct SafeHandle {
  HANDLE Handle = nullptr;

  SafeHandle() = default;
  SafeHandle( HANDLE Handle ) : Handle( Handle ) {}

  ~SafeHandle() {
    if ( Handle && Handle != INVALID_HANDLE_VALUE ) {
      CloseHandle( Handle );
    }
  }

  SafeHandle( const SafeHandle& ) = delete;
  SafeHandle& operator=( const SafeHandle& ) = delete;

  operator HANDLE() const {
    return Handle;
  }

  explicit operator bool() const {
    return Handle != nullptr && Handle != INVALID_HANDLE_VALUE;
  }
};
