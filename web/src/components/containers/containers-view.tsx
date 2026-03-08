import { memo, useMemo } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { HistorySummary } from "@/types/connection"
import { formatBytes } from "@/lib/format"

type ContainersViewProps = {
    summary: HistorySummary | null
    onSelectContainer: (id: string) => void
}

export const ContainersView = memo(({ summary, onSelectContainer }: ContainersViewProps) => {
    const rows = useMemo(() => {
        if (!summary?.perContainer) {
            return []
        }

        return Object.entries(summary.perContainer)
            .map(([key, entry]) => {
                const id = entry.id || key
                const name = entry.name || (id === "host" ? "Host" : id)
                const image = entry.image || "-"
                const pid = entry.pid ? entry.pid : null
                const topDestinations = (entry.topDestinations || []).map((talker) => talker.addr).join(", ") || "-"

                return {
                    id,
                    name,
                    image,
                    pid,
                    connections: entry.connections,
                    bytesIn: entry.bytesIn,
                    bytesOut: entry.bytesOut,
                    topDestinations,
                }
            })
            .sort((a, b) => b.connections - a.connections)
    }, [summary])

    return (
        <div className="space-y-4">
            <Card>
                <CardHeader>
                    <CardTitle>Containers Overview</CardTitle>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Container</TableHead>
                                <TableHead>Image</TableHead>
                                <TableHead>PID</TableHead>
                                <TableHead>Connections</TableHead>
                                <TableHead>Bytes In</TableHead>
                                <TableHead>Bytes Out</TableHead>
                                <TableHead>Top Destinations</TableHead>
                                <TableHead></TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {rows.map((row) => (
                                <TableRow key={row.id}>
                                    <TableCell className="font-medium">{row.name}</TableCell>
                                    <TableCell>{row.image}</TableCell>
                                    <TableCell>{row.pid ?? "-"}</TableCell>
                                    <TableCell>{row.connections.toLocaleString()}</TableCell>
                                    <TableCell>{formatBytes(row.bytesIn)}</TableCell>
                                    <TableCell>{formatBytes(row.bytesOut)}</TableCell>
                                    <TableCell className="max-w-[240px] truncate">{row.topDestinations}</TableCell>
                                    <TableCell>
                                        <Button variant="outline" size="sm" onClick={() => onSelectContainer(row.id)}>
                                            View connections
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    )
})
