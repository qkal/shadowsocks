# shadowsocks

A Zig rewrite of Shadowsocks with thin `sslocal` and `ssserver` frontends.

## Status

- Zig-first rewrite in progress
- MVP target: classic AEAD only
- Local mode: SOCKS5 `CONNECT` and `UDP ASSOCIATE`
- Transport: TCP and UDP relay
- GitHub Actions builds native downloadable artifacts for Linux, Windows, and macOS

## Build locally

```bash
zig fmt --check .
zig build check
zig build test
zig build -Doptimize=ReleaseSafe
```

## Download binaries

Pushes to `main` publish downloadable workflow artifacts from the `Build Artifacts` workflow.

## Example config

The file at `examples/config.json` shows the supported single-server MVP config shape.

## Scope

This repo intentionally does not include the old Rust workspace, crates, or service surface. The Zig port is being delivered incrementally with a smaller, easier-to-reason-about core.
