# OpenSteam Pattern Dumper

Automated tool for extracting function signature patterns from Steam client DLLs.

## What it does

1. **Installs Steam** using `SteamSetup.exe` on a Windows runner
2. **Extracts** `steamclient64.dll` and `steamui.dll`
3. **Scans** DLLs for known function signatures
4. **Generates** TOML pattern files compatible with OpenSteamTool
5. **Generates** IPC interface layout files

## Output

The tool produces:
- `steamclient_{sha256}.toml` - Function patterns for steamclient64.dll
- `steamui_{sha256}.toml` - Function patterns for steamui.dll  
- `ipc_steamclient_{sha256}.toml` - IPC interface layouts
- `summary.json` - Results summary

## Usage

### Automatic (GitHub Actions)
The workflow runs automatically every 6 hours or can be triggered manually.

### Manual
```bash
# Install dependencies
pip install pefile

# Run the dumper
python dump_patterns.py \
  --steamclient-dll /path/to/steamclient64.dll \
  --steamui-dll /path/to/steamui.dll \
  --output-dir output/patterns
```

## Pattern Format

```toml
[0xD05E26A2]
name = "CheckAppOwnership"
rva = "0x9B6A80"
sig = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57"
```

- **Section key**: CRC32-like hash of function name
- **name**: Function name
- **rva**: Relative Virtual Address (changes per build)
- **sig**: Byte signature with wildcards (stable across builds)

## IPC Format

```toml
[IClientUser]
interface_id = 0
vtable_rva = "0x12DC200"

[IClientUser.GetSteamID]
method_index = 10
funcHash = "0xD6FC3200"
wrapper_rva = "0x776FC0"
```

## Tracked Functions

### steamclient64.dll (25+ functions)
- CheckAppOwnership
- ConfigStoreGetBinary
- BuildDepotDependency
- IPCProcessMessage
- BBuildAndAsyncSendFrame
- RecvPkt
- SendCallbackToPipe
- SpawnProcess
- GetPackageInfo
- MarkLicenseAsChanged
- ProcessPendingLicenseUpdates
- And more...

### steamui.dll (10 functions)
- FillInAppOverview
- BuildCompleteAppOverviewChange
- CSteamUIAppControllerRunFrame
- GetAppByID
- MarkAppChange
- RepeatedFieldUint32_Add
- ShouldShowAppInLibrary
- AddProtobufAsBinary
- GetTopManager
- LoadModuleWithPath

## License

MIT
# re-trigger
