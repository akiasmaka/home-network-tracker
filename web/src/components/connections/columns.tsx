import type { ColumnDef } from "@tanstack/react-table"

import { Badge } from "@/components/ui/badge"
import type { Connection } from "@/types/connection"
import { directionLabel, formatBytes, protocolLabel } from "@/lib/format"

export const connectionColumns: ColumnDef<Connection>[] = [
    {
        accessorKey: "saddr",
        header: "Source",
    },
    {
        accessorKey: "addr",
        header: "Destination",
    },
    {
        accessorKey: "ifname",
        header: "Interface",
        cell: ({ row }) => row.original.ifname || `ifindex-${row.original.ifindex}`,
    },
    {
        accessorKey: "direction",
        header: "Direction",
        cell: ({ row }) => {
            const label = directionLabel(row.original.direction)
            return <Badge variant={label === "ingress" ? "default" : "secondary"}>{label}</Badge>
        },
    },
    {
        accessorKey: "proto",
        header: "Proto",
        cell: ({ row }) => {
            const label = protocolLabel(row.original.proto)
            return <Badge variant={label === "tcp" ? "default" : "secondary"}>{label}</Badge>
        },
    },
    {
        accessorKey: "bytes",
        header: "Bytes",
        cell: ({ row }) => formatBytes(row.original.bytes),
    },
    {
        accessorKey: "packets",
        header: "Packets",
    },
    {
        accessorKey: "container",
        header: "Container",
        cell: ({ row }) => row.original.container?.name || "Host",
    },
]
