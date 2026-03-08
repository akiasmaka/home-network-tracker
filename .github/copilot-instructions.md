# Home Network Tracker - Copilot Instructions

## Repository Summary

Network traffic monitoring using eBPF/XDP probes with a Go userspace loader and a React web UI. The Go service loads BPF programs, tracks IPv4/IPv6 connections, resolves hostnames, and serves a JSON/WebSocket API for the UI.

## High-Level Repo Info

- Type: eBPF/XDP probe code (C) + Go service + React/Vite web UI.
- Size: large; includes a libbpf-bootstrap git submodule and vendored Go deps.
- Languages: C (eBPF), Go (loader + API), TypeScript/React (web), shell, Docker.
- Target runtime: Linux with eBPF; Docker-based build pipeline.

## Build, Test, Run (Verified From Scripts)

All build steps are orchestrated by `build/build.sh` and assume Docker is available.
Always run from the repo root.

### Bootstrap / Prereqs

- Always initialize submodules first (required for libbpf-bootstrap):
  - `git submodule update --init --recursive`
- Build the Docker builder image (Go 1.25.7, clang, cmake, libelf/libdw/zlib/zstd):
  - `./build/build.sh --build-builder-image`

### Clean

- Clean CMake outputs (requires builder image):
  - `docker run -it --rm -w "$PWD/build" -v "$PWD:$PWD" builder make clean`
- After clean, rerun cmake generation + probe build.

### Build

- Generate CMake files and build probes (produces BPF objects + skeletons in `build/`):
  - `./build/build.sh --generate-cmake --build-probe`
- Build the Go loader (produces `go-loader/go-loader`):
  - `./build/build.sh --build-loader`
- Build the web UI (uses Node 20 + corepack/pnpm in Docker; deletes `web/node_modules` first):
  - `./build/build.sh --build-web`
- Build runtime image (requires BPF objects + Go loader):
  - `./build/build.sh --build-app-image`
- One-shot full build (preferred for fresh setups):
  - `./build/build.sh --all`


### Tests

- Only repo-local test is an integration test:
  - `go test ./tools/integration`
  - Requires Docker, cgroup v2, and a built app image `homenetworktracker:latest` (run `./build/build.sh --all` first).
  - Test starts privileged containers and polls `http://localhost:5000/data`.
- Submodule workflows exist under `libbpf-bootstrap`, but no root GitHub Actions workflows are defined.

### Run

- Run the loader directly (requires BPF build outputs):
  - `./go-loader/go-loader`
- Container run (from `tools/integration` and Dockerfile pattern):
  - `docker run -d --name homenetworktracker --privileged --network host --pid host --cgroupns host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /var/run/docker.sock:/var/run/docker.sock homenetworktracker:latest`
- API endpoints (Go server):
  - JSON: `GET /data`
  - WebSocket: `GET /ws`
  - History: `GET /api/history?range=...`
- History storage: `HISTORY_PATH` env var (default `/history/history.json`).

To run the full app use:

```
docker run --privileged -d --pid host --network host --cgroupns=host   -v /sys/fs/cgroup:/sys/fs/cgroup:ro   -v /var/run/docker.sock:/var/run/docker.sock   -v "$(pwd)/history:/history"   homenetworktracker:latest
```

## Project Layout and Key Files

### Core Architecture

- eBPF probes and CMake build:
  - `probe/xdp.bpf.c`, `probe/dns_sniffer.bpf.c`, `probe/kprobe.bpf.c`
  - `probe/CMakeLists.txt`
- Go loader entry and core logic:
  - `go-loader/cmd/main.go` (BPF loading + HTTP server + history bootstrap)
  - `go-loader/pkg/bpf/bpf_runner.go` (BPF module wrapper)
  - `go-loader/pkg/tracker/connection_tracker.go` (connection tracking + persistence)
  - `go-loader/pkg/network/ip.go` (key layouts and kernel map encoding)
  - `go-loader/pkg/output/output.go` (HTTP + WS API)
- Web UI:
  - `web/src/` (React app), `web/index.html`
  - `web/vite.config.ts`, `web/tsconfig*.json`, `web/eslint.config.js`, `web/tailwind.config.ts`, `web/postcss.config.cjs`

### Build/Config Locations

- Build orchestration: `build/build.sh`, `build/Dockerfile.builder`
- App image: `Dockerfile`
- Go module: `go-loader/go.mod` (Go 1.25.0)
- Web package: `web/package.json` (Vite + React 19 + Tailwind)

### Repository Root Contents (Top Level)

- Files: `Dockerfile`, `README.md`, `data.json`, `.gitmodules`
- Directories: `.github/`, `build/`, `go-loader/`, `probe/`, `tools/`, `web/`, `libbpf-bootstrap/`, `libbpf/`, `history/`

### Notes and Pitfalls

- `build/`, `web/dist/`, `web/node_modules/`, and `go-loader/vendor/` are generated or vendored; avoid editing by hand.
- The build script assumes the builder image is named `builder` and uses Docker-mounted paths.
- Web build inside Docker sets `PNPM_STORE_DIR=/tmp/.pnpm-store` and removes `web/node_modules` before install.

## README Summary

- Root README is minimal: "Small network tracker to monitor traffic on personal servers." (no detailed build steps).
- Web README is the default Vite template and does not describe repo-specific behavior.

## Guidance for Agents

- Trust this document first; only search the codebase if information here is missing or incorrect.
- Prefer `./build/build.sh --all` for a reliable full build path.
