import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import type { Connection } from "@/types/connection"
import { directionLabel, formatBytes, protocolLabel } from "@/lib/format"

const detailRow = (label: string, value: string) => (
    <div className="flex items-center justify-between gap-4 text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="text-foreground">{value}</span>
    </div>
)

type ConnectionDetailProps = {
    connection: Connection | null
    onOpenChange: (open: boolean) => void
}

export const ConnectionDetail = ({ connection, onOpenChange }: ConnectionDetailProps) => (
    <Dialog open={Boolean(connection)} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-lg">
            <DialogHeader>
                <DialogTitle>Connection Detail</DialogTitle>
            </DialogHeader>
            {connection ? (
                <div className="space-y-3">
                    {detailRow("Source", connection.saddr)}
                    {detailRow("Destination", connection.addr)}
                    {detailRow("Interface", connection.ifname || `ifindex-${connection.ifindex}`)}
                    {detailRow("Direction", directionLabel(connection.direction))}
                    {detailRow("Protocol", protocolLabel(connection.proto))}
                    {detailRow("Bytes", formatBytes(connection.bytes))}
                    {detailRow("Packets", connection.packets.toLocaleString())}
                    {detailRow("Container", connection.container?.name || "Host")}
                    <Separator />
                    {detailRow("Source Host", connection.sHost?.join(", ") || "-")}
                    {detailRow("Destination Host", connection.dHost?.join(", ") || "-")}
                </div>
            ) : null}
        </DialogContent>
    </Dialog>
)
