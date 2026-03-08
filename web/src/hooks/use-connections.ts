import { useEffect, useMemo, useRef, useState } from "react"

import type { Connection, ConnectionsResponse } from "@/types/connection"

type ConnectionsFilters = {
    interface: string
    direction: string
    proto: string
    container: string
    search: string
    sort: string
    order: "asc" | "desc"
    page: number
    pageSize: number
}

type UseConnectionsResult = {
    connections: Connection[]
    total: number
    loading: boolean
}

const buildQuery = (filters: ConnectionsFilters) => {
    const params = new URLSearchParams()
    if (filters.interface && filters.interface !== "all") {
        params.set("interface", filters.interface)
    }
    if (filters.direction && filters.direction !== "all") {
        params.set("direction", filters.direction)
    }
    if (filters.proto && filters.proto !== "all") {
        params.set("proto", filters.proto)
    }
    if (filters.container && filters.container !== "all") {
        params.set("container", filters.container)
    }
    if (filters.search.trim()) {
        params.set("search", filters.search.trim())
    }
    if (filters.sort) {
        params.set("sort", filters.sort)
    }
    if (filters.order) {
        params.set("order", filters.order)
    }
    params.set("page", String(filters.page))
    params.set("pageSize", String(filters.pageSize))
    return params.toString()
}

export const useConnections = (filters: ConnectionsFilters, enabled = true): UseConnectionsResult => {
    const [connections, setConnections] = useState<Connection[]>([])
    const [total, setTotal] = useState(0)
    const [loading, setLoading] = useState(false)
    const abortRef = useRef<AbortController | null>(null)

    const queryString = useMemo(() => buildQuery(filters), [filters])

    useEffect(() => {
        if (!enabled) {
            return () => undefined
        }

        let active = true

        const load = async () => {
            try {
                abortRef.current?.abort()
                const controller = new AbortController()
                abortRef.current = controller
                setLoading(true)

                const response = await fetch(`/api/connections?${queryString}`, { signal: controller.signal })
                if (!active) return

                if (!response.ok) {
                    return
                }

                const payload = (await response.json()) as ConnectionsResponse
                if (active) {
                    setConnections(payload?.data ?? [])
                    setTotal(payload?.total ?? 0)
                }
            } catch {
                // Ignore aborted or failed requests.
            } finally {
                if (active) {
                    setLoading(false)
                }
            }
        }

        load()
        const interval = window.setInterval(load, 5000)

        return () => {
            active = false
            window.clearInterval(interval)
            abortRef.current?.abort()
        }
    }, [queryString, enabled])

    return { connections, total, loading }
}
