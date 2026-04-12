#pragma once

enum class LogLevel {
  Success,
  Step,
  Info,
  Error,
};

namespace Detail {
  inline WORD ColorFor( LogLevel Level ) noexcept {
    switch ( Level ) {
      case LogLevel::Success: return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
      case LogLevel::Step:    return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
      case LogLevel::Info:    return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
      case LogLevel::Error:   return FOREGROUND_RED | FOREGROUND_INTENSITY;
      default:                return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
  }

  inline std::string_view PrefixFor( LogLevel Level ) noexcept {
    switch ( Level ) {
      case LogLevel::Success: return "[+]";
      case LogLevel::Step:    return "[*]";
      case LogLevel::Info:    return "[~]";
      case LogLevel::Error:   return "[-]";
      default:                return "[?]";
    }
  }

  inline void WriteBytes( HANDLE Out, std::string_view Text ) noexcept {
    DWORD Written = 0;
    WriteFile( Out, Text.data(), static_cast<DWORD>( Text.size() ), &Written, nullptr );
  }

  inline void WriteLine( LogLevel Level, std::string_view Message ) noexcept {
    auto Out = GetStdHandle( STD_OUTPUT_HANDLE );

    if ( Out == INVALID_HANDLE_VALUE ) {
      return;
    }

    //
    // Color the prefix if we're writing to a real console.
    //
    DWORD Mode = 0;

    bool IsConsole = GetConsoleMode( Out, &Mode ) != 0;

    if ( IsConsole ) {
      CONSOLE_SCREEN_BUFFER_INFO Info{};
      bool HaveInfo = GetConsoleScreenBufferInfo( Out, &Info ) != 0;

      SetConsoleTextAttribute( Out, ColorFor( Level ) );
      WriteBytes( Out, PrefixFor( Level ) );

      if ( HaveInfo ) {
        SetConsoleTextAttribute( Out, Info.wAttributes );
      }
    } else {
      WriteBytes( Out, PrefixFor( Level ) );
    }

    WriteBytes( Out, " " );
    WriteBytes( Out, Message );
    WriteBytes( Out, "\n" );
  }

  template <typename... Args>
  void Log( LogLevel Level, std::format_string<Args...> Fmt, Args&&... A ) {
    WriteLine( Level, std::format( Fmt, std::forward<Args>( A )... ) );
  }

  inline void Log( LogLevel Level, std::string_view Message ) {
    WriteLine( Level, Message );
  }
} // namespace Detail

#define LOG_OK( ... )    ::Detail::Log( LogLevel::Success, __VA_ARGS__ )
#define LOG_STEP( ... )  ::Detail::Log( LogLevel::Step, __VA_ARGS__ )
#define LOG_INFO( ... )  ::Detail::Log( LogLevel::Info, __VA_ARGS__ )
#define LOG_ERROR( ... ) ::Detail::Log( LogLevel::Error, __VA_ARGS__ )
