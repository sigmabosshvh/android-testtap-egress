# android-testtap-egress
PoC for packet-level Internet egress through an AOSP test TAP and Android Ethernet tethering using Shizuku.

The original proof of concept was completed on August 16, 2026. This writeup was prepared later after cleaning up the code, adding a few diagnostic checks, and documenting the technique.

## Technical writeup
See [docs/writeup.md](docs/writeup.md).

## Requirements
- Android device
- Shizuku started through ADB
- Internet connectivity
- Compatible Android Ethernet/TestNetwork framework implementation
