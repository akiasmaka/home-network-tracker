import { useCallback, useEffect, useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Toggle } from "@/components/ui/toggle"
import { cn } from "@/lib/utils"
import { useWebSocket } from "@/hooks/use-websocket"
import { ConnectionsView } from "@/components/connections/connections-view"
import { ContainersView } from "@/components/containers/containers-view"
import { DashboardView } from "@/components/dashboard/dashboard-view"

const App = () => {
  const [range, setRange] = useState("24h")
  const [activeTab, setActiveTab] = useState("dashboard")
  const [selectedContainer, setSelectedContainer] = useState<string | null>(null)
  const [theme, setTheme] = useState<"dark" | "light">("dark")

  const { summary, connected } = useWebSocket()

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark")
  }, [theme])

  const handleContainerSelect = useCallback((id: string) => {
    setSelectedContainer(id)
    setActiveTab("connections")
  }, [])

  const handleRangeChange = useCallback((value: string) => {
    setRange(value)
  }, [])

  const navItems = [
    {
      id: "dashboard",
      label: "Dashboard",
      description: "Traffic insights and system summaries.",
    },
    {
      id: "connections",
      label: "Connections",
      description: "Live flows and detailed connection data.",
    },
    {
      id: "containers",
      label: "Containers",
      description: "Container activity and top destinations.",
    },
  ]

  const activeNav = navItems.find((item) => item.id === activeTab) ?? navItems[0]

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="grid min-h-screen lg:grid-cols-[240px_1fr]">
        <aside className="hidden border-r bg-muted/40 lg:block">
          <div className="flex h-14 items-center border-b px-6 text-sm font-semibold">
            Home Network Tracker
          </div>
          <nav className="space-y-1 p-4">
            {navItems.map((item) => (
              <Button
                key={item.id}
                variant={activeTab === item.id ? "secondary" : "ghost"}
                className="w-full justify-start"
                onClick={() => setActiveTab(item.id)}
              >
                {item.label}
              </Button>
            ))}
          </nav>
        </aside>
        <div className="flex min-w-0 flex-col">
          <header className="flex h-14 items-center gap-4 border-b bg-background px-6">
            <div className="text-sm font-semibold">{activeNav.label}</div>
            <div className="ml-auto flex items-center gap-2">
              <Badge variant={connected ? "default" : "secondary"} className={connected ? "animate-pulse" : ""}>
                {connected ? "ws connected" : "ws disconnected"}
              </Badge>
              <Toggle pressed={theme === "dark"} onPressedChange={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))} aria-label="Toggle theme">
                {theme === "dark" ? "Dark" : "Light"}
              </Toggle>
            </div>
          </header>
          <main className="flex-1 space-y-6 p-6">
            <div className="flex flex-col gap-2">
              <h1 className="text-2xl font-semibold">{activeNav.label}</h1>
              <p className="text-sm text-muted-foreground">{activeNav.description}</p>
            </div>
            <div className="flex flex-wrap gap-2 lg:hidden">
              {navItems.map((item) => (
                <Button
                  key={item.id}
                  variant={activeTab === item.id ? "secondary" : "ghost"}
                  size="sm"
                  onClick={() => setActiveTab(item.id)}
                  className={cn("justify-start", activeTab === item.id && "shadow-sm")}
                >
                  {item.label}
                </Button>
              ))}
            </div>
            {activeTab === "dashboard" ? (
              <DashboardView summary={summary} range={range} onRangeChange={handleRangeChange} />
            ) : null}
            {activeTab === "connections" ? (
              <ConnectionsView summary={summary} selectedContainer={selectedContainer} />
            ) : null}
            {activeTab === "containers" ? (
              <ContainersView summary={summary} onSelectContainer={handleContainerSelect} />
            ) : null}
          </main>
        </div>
      </div>
    </div>
  )
}

export default App
