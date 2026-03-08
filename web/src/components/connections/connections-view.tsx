import { memo, useEffect, useMemo, useState } from "react"
import type { SortingState } from "@tanstack/react-table"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { Connection } from "@/types/connection"
import type { HistorySummary } from "@/types/connection"
import { useConnections } from "@/hooks/use-connections"

import { connectionColumns } from "./columns"
import { ConnectionDetail } from "./connection-detail"
import { DataTable } from "./data-table"

type ConnectionsViewProps = {
    summary: HistorySummary | null
    selectedContainer?: string | null
}

const pageSize = 50

export const ConnectionsView = memo(({ summary, selectedContainer }: ConnectionsViewProps) => {
    const [selected, setSelected] = useState<Connection | null>(null)
    const [interfaceFilter, setInterfaceFilter] = useState("all")
    const [directionFilter, setDirectionFilter] = useState("all")
    const [protocolFilter, setProtocolFilter] = useState("all")
    const [containerFilter, setContainerFilter] = useState(selectedContainer || "host")
    const [search, setSearch] = useState("")
    const [pageIndex, setPageIndex] = useState(0)
    const [sorting, setSorting] = useState<SortingState>([{ id: "bytes", desc: true }])

    useEffect(() => {
        if (selectedContainer) {
            setContainerFilter(selectedContainer)
            setPageIndex(0)
        }
    }, [selectedContainer])

    const interfaces = useMemo(() => {
        const entries = summary?.perInterface ? Object.keys(summary.perInterface) : []
        return entries.sort()
    }, [summary])

    const containers = useMemo(() => {
        const entries = new Map<string, string>()
        if (summary?.perContainer) {
            Object.entries(summary.perContainer).forEach(([key, container]) => {
                const id = container.id || key
                const label = container.name || (id === "host" ? "Host" : id)
                entries.set(id, label)
            })
        }
        if (!entries.has("host")) {
            entries.set("host", "Host")
        }
        return Array.from(entries.entries())
    }, [summary])

    const activeSort = sorting[0] ?? { id: "bytes", desc: true }
    const filters = useMemo(() => {
        const order = activeSort.desc ? "desc" : "asc"
        return {
            interface: interfaceFilter,
            direction: directionFilter,
            proto: protocolFilter,
            container: containerFilter,
            search,
            sort: activeSort.id ?? "bytes",
            order: order as "asc" | "desc",
            page: pageIndex,
            pageSize,
        }
    }, [interfaceFilter, directionFilter, protocolFilter, containerFilter, search, sorting, pageIndex])
    const { connections, total } = useConnections(filters)

    const pageCount = Math.max(1, Math.ceil(total / pageSize))

    useEffect(() => {
        setPageIndex(0)
    }, [interfaceFilter, directionFilter, protocolFilter, containerFilter, search, sorting])

    return (
        <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-4">
                <Select value={interfaceFilter} onValueChange={setInterfaceFilter}>
                    <SelectTrigger>
                        <SelectValue placeholder="Interface" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All interfaces</SelectItem>
                        {interfaces.map((iface) => (
                            <SelectItem key={iface} value={iface}>
                                {iface}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
                <Select value={directionFilter} onValueChange={setDirectionFilter}>
                    <SelectTrigger>
                        <SelectValue placeholder="Direction" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All directions</SelectItem>
                        <SelectItem value="ingress">Ingress</SelectItem>
                        <SelectItem value="egress">Egress</SelectItem>
                    </SelectContent>
                </Select>
                <Select value={protocolFilter} onValueChange={setProtocolFilter}>
                    <SelectTrigger>
                        <SelectValue placeholder="Protocol" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All protocols</SelectItem>
                        <SelectItem value="tcp">TCP</SelectItem>
                        <SelectItem value="udp">UDP</SelectItem>
                        <SelectItem value="other">Other</SelectItem>
                    </SelectContent>
                </Select>
                <Select value={containerFilter} onValueChange={setContainerFilter}>
                    <SelectTrigger>
                        <SelectValue placeholder="Container" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All containers</SelectItem>
                        {containers.map(([id, name]) => (
                            <SelectItem key={id} value={id}>
                                {name}
                            </SelectItem>
                        ))}
                    </SelectContent>
                </Select>
            </div>

            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <CardTitle>Connection Activity</CardTitle>
                    <div className="text-sm text-muted-foreground">{total.toLocaleString()} total</div>
                </CardHeader>
                <CardContent>
                    <DataTable
                        columns={connectionColumns}
                        data={connections}
                        onRowClick={setSelected}
                        searchValue={search}
                        onSearchChange={setSearch}
                        sorting={sorting}
                        onSortingChange={setSorting}
                        pageIndex={pageIndex}
                        pageCount={pageCount}
                        onPageChange={(nextPage) => setPageIndex(Math.min(Math.max(nextPage, 0), pageCount - 1))}
                    />
                </CardContent>
            </Card>
            <ConnectionDetail connection={selected} onOpenChange={(open) => !open && setSelected(null)} />
        </div>
    )
})
