# LegacyJB

LegacyJB is a PS5 payload that provides a jailbreak service for supported applications. This repository includes the payload source and the libraries required to build it with CMake.

## Project structure

```text
.
|-- CMakeLists.txt
|-- include/
|-- legacyjb/
|-- libhijacker/
|-- libNidResolver/
`-- libSelfDecryptor/
```

The build produces:

```text
bin/LegacyJB.elf
bin/LegacyJB.bin
```

## Requirements

- Linux or WSL on Windows
- CMake 3.20 or newer
- Ninja or GNU Make
- PS5 Payload SDK configured through `PS5_PAYLOAD_SDK`
- The SDK CMake toolchain, normally located at `$PS5_PAYLOAD_SDK/toolchain/prospero.cmake`

The project is configured and tested with PS5 Payload SDK `v0.43`.

## Build on Linux or WSL

Set the SDK path:

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
```

Configure the project with Ninja:

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE="$PS5_PAYLOAD_SDK/toolchain/prospero.cmake" \
  -DV_FW=0x320
```

To use GNU Make instead:

```bash
cmake -S . -B build -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_TOOLCHAIN_FILE="$PS5_PAYLOAD_SDK/toolchain/prospero.cmake" \
  -DV_FW=0x320
```

Build LegacyJB:

```bash
cmake --build build --target legacyjb -j"$(nproc)"
```

The output files are written to `bin/`.

## Build from PowerShell with WSL

Configure with Ninja:

```powershell
wsl -e bash -lc "cd '/mnt/c/Projects/LegacyJB' && export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk && cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=`$PS5_PAYLOAD_SDK/toolchain/prospero.cmake -DV_FW=0x320"
```

If Ninja is not installed in WSL, use GNU Make:

```powershell
wsl -e bash -lc "cd '/mnt/c/Projects/LegacyJB' && export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk && cmake -S . -B build -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=`$PS5_PAYLOAD_SDK/toolchain/prospero.cmake -DV_FW=0x320"
```

Then build the payload:

```powershell
wsl -e bash -lc "cd '/mnt/c/Projects/LegacyJB' && cmake --build build --target legacyjb -j`$(nproc)"
```

## Target firmware

`V_FW` defines the `PS5_FW_VERSION` compatibility macro during compilation. The default value is `0x1360`.

Kernel addresses are resolved at runtime by PS5 Payload SDK `v0.43`. SELF decryption includes pager-table mappings through firmware `13.60`, so one build can run across the firmware versions recognized by the SDK.

Examples:

```bash
-DV_FW=0x320
-DV_FW=0x900
-DV_FW=0x1360
```

Use a value supported by the SDK and by the offsets available for your environment.

## Usage

Send `bin/LegacyJB.elf` or `bin/LegacyJB.bin` using your preferred PS5 payload loader.

When started, the payload:

- opens a TCP jailbreak service on port `9028`;
- monitors file-based requests from supported applications;
- writes logs to `/user/data/legacy_jb.log`;
- rotates the previous log to `/user/data/legacy_jb.prev.log`;
- enables Homebrew Store and Itemzflow compatibility.

## GitHub Actions

The workflow at `.github/workflows/build.yml` builds the `legacyjb` target on GitHub.

By default, it downloads PS5 Payload SDK `v0.43` from:

```text
https://github.com/ps5-payload-dev/sdk/releases/download/v0.43/ps5-payload-sdk.zip
```

To use another release, create a repository variable named `PS5_PAYLOAD_SDK_URL` containing the desired SDK ZIP URL.

You can select the firmware in either of these ways:

- enter `firmware` when manually running the workflow;
- create a repository variable named `PS5_FW_VERSION`.

After a successful build, the workflow publishes an artifact named `LegacyJB` containing `LegacyJB.elf` and `LegacyJB.bin`.

## Troubleshooting

### `PS5_PAYLOAD_SDK is not set`

Set the variable before configuring CMake:

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
```

### `prospero.cmake` was not found

Verify that the SDK was extracted to the expected directory:

```bash
ls "$PS5_PAYLOAD_SDK/toolchain/prospero.cmake"
```

### The `.bin` file is not recreated after manual deletion

Force a clean rebuild:

```bash
cmake --build build --target legacyjb --clean-first -j"$(nproc)"
```
