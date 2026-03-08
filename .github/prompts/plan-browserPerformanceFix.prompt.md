# Plan: Fix Browser Memory/CPU Explosion

**TL;DR**: Three compounding issues are causing the 3GB memory / 20% CPU problem:

1. **History polling every 1 second fetches massive JSON payloads** — For a 24h range (the default), the backend returns ~1,440 `Snapshot` objects (1m resolution for 23h + 3,600 raw 1s snapshots for the last hour). Each snapshot contains nested maps (`perInterface`, `perProtocol`, `perContainer`, `topTalkers`). Every second, `useHistory` fetches, parses, and replaces these snapshots even when nothing changed (ETag only helps on 304s but there's a new snapshot every second so it almost never matches).

2. **WebSocket pushes the full connection list every second** — The backend broadcasts ALL tracked connections every 1s. With thousands of connections (eBPF on a busy host), this is a large JSON payload parsed and stored in React state every second. Each `setConnections(payload)` triggers a re-render of the entire component tree since `connections` flows to every tab component (dashboard, connections, containers) — all computing `useMemo` derivations on every update.

3. **The DataTable search filter uses `JSON.stringify` on every row** — In [data-table.tsx](web/src/components/connections/data-table.tsx#L27), when there's any global filter text, it runs `JSON.stringify(row).toLowerCase()` for every connection. Even without a filter, the table re-creates on every 1s WebSocket update because `data` (the `filteredConnections` array) is always a new reference.

## Architecture Note

Live connections live in a Go `sync.Map` in memory. Every 1 second the backend serializes the **entire** map to JSON and broadcasts it to every WebSocket client — this is the main source of the memory explosion. SQLite is only used for historical snapshots (the `history` package). There is currently **no** server-side filtering or pagination for live connection data.

## Steps

### 1. Add a server-side `/api/connections` query endpoint (Go backend)

Create `GET /api/connections` that filters and paginates from the in-memory `sync.Map`. Query parameters:
- `interface` — filter by interface name
- `direction` — `ingress` | `egress`
- `proto` — `tcp` | `udp` | `other`
- `container` — container ID (`host` for host connections)
- `search` — substring match on saddr, addr, hostnames, container name
- `page` / `pageSize` — pagination (default page=0, pageSize=50)
- `sort` / `order` — sort field and direction

Return shape: `{ data: Connection[], total: number }` so the frontend knows total pages.

This moves the heavy lifting (filtering, sorting, pagination) to Go where it's cheap, and sends only ~50 rows of JSON to the browser instead of thousands.

### 2. Refactor connections tab to fetch-on-demand

Replace the current approach where `ConnectionsView` receives the full `connections[]` prop from the WebSocket:
- Create a new `useConnections(filters)` hook that calls `/api/connections` with the current filter state.
- Fetch only when the connections tab is active **and** when filters change.
- Default the container filter to `"host"` when the tab first opens (so users see only host connections by default).
- Poll at a reasonable interval (e.g., every 5s) while the tab is active, or use a manual refresh button.
- Remove `connections` as a prop from `ConnectionsView` entirely.

### 3. Slim down the WebSocket payload to summary-only

The WebSocket currently broadcasts the full connection list (thousands of rows) every 1s. Change it to broadcast only a **summary object** (the same shape as `HistorySummary`):
- `totalConnections`, `bytesIn`, `bytesOut`, `packetsIn`, `packetsOut`
- `uniqueSrcIps`, `uniqueDstIps`
- `perInterface`, `perProtocol`, `perContainer`, `topTalkers`

This is what `DashboardView` and `ContainersView` actually need. The summary is tiny (~1-2 KB) versus the full connection list (potentially megabytes). The Go backend already has `summarizeConnections()` in the history package — reuse it in the broadcast loop.

**Dashboard stat cards are already computed server-side:** The `stats` useMemo in `DashboardView` iterates the full connection array client-side to compute `totalConnections`, `bytesIn/Out`, `uniqueSrcIps/DstIps` — but `summarizeConnections()` in Go already produces the exact same fields. Likewise `talkers`, `containerTalkers`, `protocolData`, and `interfaceData` are all re-derived client-side from raw connections when the summary already contains `topTalkers`, `perContainer`, `perProtocol`, and `perInterface`. After this change, `DashboardView` can simply read the summary object directly — **all six `useMemo` blocks that iterate `connections` can be deleted** and replaced with direct property access on the summary.

### 4. Drive containers tab from the WS summary (no full connection list)

`ContainersView` currently receives the full `connections[]` and iterates it twice to compute per-container stats + top destinations. With the WS payload already containing `perContainer` (step 3), extend the Go-side `ContainerSummary` to include the missing fields:
- `image` — container image name (already available from `containermeta.ContainerInfo`)
- `pid` — container PID (same source)
- `topDestinations` — top 3 destination IPs by bytes (compute server-side during `summarizeConnections()`)

Then `ContainersView` consumes the summary object directly instead of the full connection list. The "View connections" button switches to the connections tab with a container filter, which fetches via `/api/connections?container=X` (step 1). No full connection list ever reaches this component.

### 5. Throttle history fetching in `useHistory`

Change the polling interval in [use-history.ts](web/src/hooks/use-history.ts#L62) from `1000ms` to at least `30000ms` (30s). Historical data doesn't change rapidly enough to justify per-second polling. The ETag mechanism already exists but rarely produces 304s because new snapshots are inserted every second.

### 6. Avoid re-rendering inactive tabs

In [App.tsx](web/src/App.tsx#L51-L59), all three tab contents receive props and compute `useMemo` derivations even when not visible. Only render the active tab's component. Since the connections tab now fetches its own data, it doesn't need `connections` from the parent at all.

### 7. Stop serializing every row in `DataTable` filter

In [data-table.tsx](web/src/components/connections/data-table.tsx#L28), replace `JSON.stringify(row).toLowerCase().includes(query)` with targeted field searches (check `saddr`, `addr`, `ifname`, `container.name`, etc. directly). With server-side search (step 1) this becomes a fallback, but it should still not use `JSON.stringify`. Better yet, move the search to the server entirely and remove client-side filtering.

### 8. Memoize child components

Wrap `DashboardView`, `ConnectionsView`, and `ContainersView` with `React.memo` so they only re-render when their actual props change (not on every parent re-render).

### 9. Reduce Recharts overhead

The dashboard renders 5 separate Recharts instances, all re-rendering on every `connections` state change (every 1s). With the WS payload slimmed to summary-only (step 3), chart data will be a stable reference between updates, reducing re-renders. Additionally:
- Guard charts behind the active-tab check (step 5).
- Disable all animations (`isAnimationActive={false}` — already done for AreaChart, apply to others).

## Data Flow: Before vs After

### Before (current)
```
WebSocket (1s) → full Connection[] (thousands of rows, megabytes) → React state → re-render everything
useHistory (1s) → full Snapshot[] (1,400+ objects) → React state → re-render charts
```

### After (proposed)
```
WebSocket (1s) → summary-only object (~1-2 KB) → React state → dashboard/containers only
/api/connections (on-demand) → filtered/paginated 50 rows → connections tab only
useHistory (30s) → Snapshot[] (same, but 30x less frequent) → dashboard charts only
```

## Verification

- After changes, open DevTools → Performance Monitor and watch JS Heap Size. It should stabilize under 100-200MB rather than climbing to 3GB.
- Check the Network tab: history fetches should happen every 30s, connections fetches only on filter/tab change plus a 5s poll.
- WebSocket messages should be tiny (~1-2 KB summary JSON per message).
- Verify Profiler tab shows no continuous re-render storm.

## Root Cause Summary

The core issue is that the backend broadcasts **every tracked connection** as raw JSON over WebSocket every second, and the frontend also polls the full history every second. This pushes megabytes of JSON into React state per second, causing the entire component tree to re-render and recompute all derived data. Each cycle allocates new objects that put enormous GC pressure on the browser, leading to the 3GB heap. The fix is to move filtering/pagination server-side, slim the WebSocket to summary data, and fetch connection details only on demand.
