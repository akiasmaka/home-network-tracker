# home-network-tracker

A network traffic monitor for personal servers built on eBPF. It attaches BPF programs to Linux cgroups to track per-connection bytes and packets for both IPv4 and IPv6, passively sniffs DNS responses for hostname resolution, enriches connections with Docker container metadata, stores historical snapshots in SQLite with automatic downsampling, and serves everything through a real-time web dashboard.

## Features

- **eBPF cgroup packet tracking** — counts bytes and packets per connection (IPv4/IPv6, TCP/UDP) at the kernel level using cgroup skb hooks
- **Passive DNS resolution** — sniffs DNS responses via a BPF socket filter to map IPs to hostnames without active lookups
- **Docker container awareness** — resolves cgroup IDs to container names/images via the Docker socket API
- **Historical time-series** — SQLite-backed snapshots with 3-tier automatic downsampling (1s → 1m → 5m)
- **REST + WebSocket API** — filtered/paginated connection queries, historical snapshots with ETag caching, and 1 Hz live summary via WebSocket
- **React dashboard** — interactive charts (traffic over time, protocol breakdown, top talkers), filterable connection table, and per-container view

## Prerequisites

- **Docker** — all build steps run inside Docker containers; no local toolchain required
- **Linux host with cgroup v2** — required for the BPF cgroup hooksdaasdasdasdadasdasd
- **Git submodules** — the build depends on vendored libbpf-bootstrap sources

## Building

### Quick start (full build)

```bash
git clone --recursive https://github.com/akiasmaka/home-network-tracker.git
cd home-network-tracker
./build/build.sh --build-builder-image
./build/build.sh --all
```

`--all` runs the complete pipeline: cmake generation → eBPF probe compilation → Go loader build → web UI build → Docker app image.

### Individual build targets

```bash
# Initialize submodules (if not cloned with --recursive)
git submodule update --init --recursive

# Build the Docker builder image (Go, clang, cmake, libelf, etc.)
./build/build.sh --build-builder-image

# Generate CMake files
./build/build.sh --generate-cmake

# Compile eBPF probes (produces .bpf.o objects + skeleton headers in build/)
./build/build.sh --build-probe

# Build the Go loader binary (produces go-loader/go-loader)
./build/build.sh --build-loader

# Build the web UI (produces web/dist/)
./build/build.sh --build-web

# Package into runtime Docker image (default: homenetworktracker:latest)
./build/build.sh --build-app-image

# Use a custom image tag
./build/build.sh --build-app-image --image-tag myregistry/tracker:v1
```

## Running

```bash
docker run -d \
  --name homenetworktracker \
  --privileged \
  --pid host \
  --network host \
  --cgroupns host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)/history:/history" \
  homenetworktracker:latest
```

The web UI and API are available at `http://<host>:5000`.

### Required container flags

| Flag | Purpose |
|------|---------|
| `--privileged` | Load BPF programs and attach to cgroups |
| `--pid host` | Access `/proc` for cgroup path resolution |
| `--network host` | Monitor host network traffic |
| `--cgroupns host` | Access host cgroup hierarchy |
| `-v /sys/fs/cgroup:...` | Read cgroup filesystem for container resolution |
| `-v /var/run/docker.sock:...` | Query Docker API for container metadata |
| `-v .../history:/history` | Persist SQLite history database across restarts |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HISTORY_PATH` | `/history/history.db` | Path to the SQLite history database |

## How It Works

eBPF programs are loaded into the kernel and attached to cgroup skb hooks, where they count bytes and packets for every IPv4/IPv6 TCP/UDP connection passing through. A separate BPF socket filter captures DNS responses for passive hostname resolution. The Go service polls the kernel maps once per second, enriches each connection with reverse-DNS hostnames and Docker container metadata, and tracks everything in an in-memory map with automatic expiration. Aggregate snapshots are stored in SQLite and automatically downsampled over time (1s → 1m → 5m resolution). The HTTP server on port 5000 exposes the data via REST and WebSocket endpoints, and serves the React dashboard for real-time visualization.
