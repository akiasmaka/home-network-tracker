import { useEffect, useRef, useState } from "react"

import type { Snapshot } from "@/types/connection"

export const useHistory = (range: string) => {
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const etagRef = useRef<string | null>(null)

  useEffect(() => {
    let active = true
    let currentController: AbortController | null = null

    // Reset ETag when range changes so the first fetch always gets fresh data.
    etagRef.current = null

    const load = async () => {
      try {
        currentController?.abort()
        const controller = new AbortController()
        currentController = controller

        const headers: Record<string, string> = {}
        if (etagRef.current) {
          headers["If-None-Match"] = etagRef.current
        }

        const response = await fetch(`/api/history?range=${range}`, {
          signal: controller.signal,
          headers,
        })

        if (!active) return

        // 304 Not Modified — data hasn't changed, keep current snapshots.
        if (response.status === 304) {
          return
        }

        if (!response.ok) {
          return
        }

        // Store the ETag for conditional requests.
        const etag = response.headers.get("ETag")
        if (etag) {
          etagRef.current = etag
        }

        const payload = (await response.json()) as Snapshot[] | null
        if (active) {
          setSnapshots(payload ?? [])
        }
      } catch {
        // Ignore aborted or failed requests.
      }
    }

    load()

    const interval = window.setInterval(load, 30000)

    return () => {
      active = false
      window.clearInterval(interval)
      currentController?.abort()
    }
  }, [range])

  return { snapshots }
}
