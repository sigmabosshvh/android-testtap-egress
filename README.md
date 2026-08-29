# android-testtap-egress
PoC for packet-level Internet egress through an AOSP test TAP and Android Ethernet tethering using Shizuku.

The original proof of concept was completed on August 16, 2026. This writeup was prepared later after cleaning up the code, adding a few diagnostic checks, and documenting the technique.

**No root.**

**No CAP_NET_RAW.**

**Arbitrary L3/L4 packet construction & egress.**

The shell-privileged part of the PoC runs as an ADB-backed Shizuku UserService under the Android `shell` UID 2000. The app itself does not obtain CAP_NET_RAW or raw-socket access; packets are constructed in userspace and forwarded through a framework-managed test TAP + tethering path.

As an end-to-end check, the PoC sends a TCP SYN with a fixed sequence number (`0x12345678`) and observes the remote SYN-ACK acknowledging `0x12345679`.

## Technical writeup
See [docs/writeup.md](docs/writeup.md).

## Requirements
- Android device
- ADB-backed Shizuku
- Internet connectivity
- Compatible Android Ethernet/TestNetwork framework implementation
