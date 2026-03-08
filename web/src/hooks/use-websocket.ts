import { useEffect, useMemo, useState } from "react"

import type { HistorySummary } from "@/types/connection"

type WebSocketState = {
  summary: HistorySummary | null
  connected: boolean
}

const buildWsUrl = () => {
  if (typeof window === "undefined") {
    return ""
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws"
  return `${protocol}://${window.location.host}/ws`
}

export const useWebSocket = (): WebSocketState => {
  const [summary, setSummary] = useState<HistorySummary | null>(null)
  const [connected, setConnected] = useState(false)
  const wsUrl = useMemo(() => buildWsUrl(), [])

  useEffect(() => {
    if (wsUrl.length === 0) {
      return () => undefined
    }

    let socket: WebSocket | null = null
    let reconnectTimer: number | undefined
    let shouldReconnect = true

    const connect = () => {
      socket = new WebSocket(wsUrl)

      socket.onopen = () => {
        setConnected(true)
      }

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as HistorySummary
          setSummary(payload)
        } catch {
          // Ignore malformed payloads.
        }
      }

      socket.onclose = () => {
        setConnected(false)
        if (shouldReconnect) {
          reconnectTimer = window.setTimeout(connect, 1000)
        }
      }

      socket.onerror = () => {
        socket?.close()
      }
    }

    connect()

    return () => {
      shouldReconnect = false
      if (reconnectTimer !== undefined) {
        window.clearTimeout(reconnectTimer)
      }
      socket?.close()
    }
  }, [wsUrl])

  return { summary, connected }
}
