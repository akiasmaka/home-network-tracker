import { memo, useMemo } from "react"
import { Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart, XAxis, YAxis } from "recharts"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { type ChartConfig, ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { HistorySummary } from "@/types/connection"
import { useHistory } from "@/hooks/use-history"
import { formatBytes, formatCount } from "@/lib/format"

const ranges = [
    { value: "1h", label: "1h" },
    { value: "6h", label: "6h" },
    { value: "24h", label: "24h" },
    { value: "7d", label: "7d" },
]

const trafficConfig = {
    bytesIn: { label: "Bytes In", color: "#7dd3fc" },
    bytesOut: { label: "Bytes Out", color: "#f9a8d4" },
} satisfies ChartConfig

const protocolConfig = {
    value: { label: "Connections", color: "#c4b5fd" },
} satisfies ChartConfig

const talkersConfig = {
    bytes: { label: "Traffic", color: "#86efac" },
} satisfies ChartConfig

const containerConfig = {
    bytes: { label: "Traffic", color: "#93c5fd" },
} satisfies ChartConfig

const interfaceConfig = {
    bytesIn: { label: "Bytes In", color: "#7dd3fc" },
    bytesOut: { label: "Bytes Out", color: "#fda4af" },
} satisfies ChartConfig

function bytesFormatter(config: ChartConfig) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (value: any, name: any, item: any) => {
        const key = String(item?.dataKey ?? name)
        const label = String(config[key]?.label ?? name)
        return (
            <div className="flex flex-1 items-center gap-2 leading-none">
                <div
                    className="h-2.5 w-2.5 shrink-0 rounded-[2px]"
                    style={{ backgroundColor: item?.color }}
                />
                <span className="text-muted-foreground">{label}</span>
                <span className="ml-auto font-mono font-medium tabular-nums text-foreground">
                    {formatBytes(Number(value))}
                </span>
            </div>
        )
    }
}

type DashboardViewProps = {
    summary: HistorySummary | null
    range: string
    onRangeChange: (value: string) => void
}

export const DashboardView = memo(({ summary, range, onRangeChange }: DashboardViewProps) => {
    const { snapshots } = useHistory(range)
    const summaryData: HistorySummary =
        summary ??
        ({
            totalConnections: 0,
            bytesIn: 0,
            bytesOut: 0,
            packetsIn: 0,
            packetsOut: 0,
            uniqueSrcIps: 0,
            uniqueDstIps: 0,
            perInterface: {},
            perProtocol: {},
            perContainer: {},
            topTalkers: [],
        } satisfies HistorySummary)

    const stats = useMemo(() => {
        return {
            totalConnections: summaryData.totalConnections,
            bytesIn: summaryData.bytesIn,
            bytesOut: summaryData.bytesOut,
            packetsIn: summaryData.packetsIn,
            packetsOut: summaryData.packetsOut,
            uniqueSrcIps: summaryData.uniqueSrcIps,
            uniqueDstIps: summaryData.uniqueDstIps,
        }
    }, [summaryData])

    const chartData = useMemo(() => {
        let lastIn = 0
        let lastOut = 0

        return snapshots.map((snapshot, index) => {
            const currentIn = snapshot.summary.bytesIn
            const currentOut = snapshot.summary.bytesOut
            const deltaIn = index === 0 ? 0 : Math.max(0, currentIn - lastIn)
            const deltaOut = index === 0 ? 0 : Math.max(0, currentOut - lastOut)

            lastIn = currentIn
            lastOut = currentOut

            return {
                ts: snapshot.timestamp,
                bytesIn: deltaIn,
                bytesOut: deltaOut,
            }
        })
    }, [snapshots])

    const talkers = useMemo(() => {
        return summaryData.topTalkers.map((entry) => ({
            addr: entry.addr,
            bytes: entry.bytes,
            label: entry.addr,
            tooltip: entry.addr,
        }))
    }, [summaryData.topTalkers])

    const containerTalkers = useMemo(() => {
        return Object.values(summaryData.perContainer)
            .map((entry) => ({
                name: entry.name || entry.id || "Host",
                bytes: entry.bytesIn + entry.bytesOut,
            }))
            .sort((a, b) => b.bytes - a.bytes)
            .slice(0, 10)
    }, [summaryData.perContainer])

    const protocolData = useMemo(() => {
        return Object.entries(summaryData.perProtocol).map(([name, value]) => ({ name, value }))
    }, [summaryData.perProtocol])

    const interfaceData = useMemo(() => {
        return Object.entries(summaryData.perInterface).map(([name, summary]) => ({
            name,
            bytesIn: summary.bytesIn,
            bytesOut: summary.bytesOut,
        }))
    }, [summaryData.perInterface])

    return (
        <div className="flex flex-col gap-6">
            <section className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader>
                        <CardTitle>Total Connections</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">
                        {formatCount(stats.totalConnections)}
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Bytes In</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">
                        {formatBytes(stats.bytesIn)}
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Bytes Out</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">
                        {formatBytes(stats.bytesOut)}
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Unique IPs</CardTitle>
                    </CardHeader>
                    <CardContent className="text-3xl font-semibold">
                        {formatCount(stats.uniqueSrcIps + stats.uniqueDstIps)}
                    </CardContent>
                </Card>
            </section>

            <section className="grid gap-4 lg:grid-cols-[2fr_1fr]">
                <Card className="h-full">
                    <CardHeader className="flex flex-row items-center justify-between">
                        <CardTitle>Traffic Over Time</CardTitle>
                        <Select value={range} onValueChange={onRangeChange}>
                            <SelectTrigger className="w-[100px]">
                                <SelectValue placeholder="Range" />
                            </SelectTrigger>
                            <SelectContent>
                                {ranges.map((item) => (
                                    <SelectItem key={item.value} value={item.value}>
                                        {item.label}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </CardHeader>
                    <CardContent className="h-[280px]">
                        <ChartContainer config={trafficConfig} className="aspect-auto h-full w-full">
                            <AreaChart data={chartData} margin={{ top: 16, left: 12, right: 16, bottom: 8 }}>
                                <XAxis
                                    dataKey="ts"
                                    type="number"
                                    scale="time"
                                    domain={["dataMin", "dataMax"]}
                                    stroke="hsl(var(--muted-foreground))"
                                    fontSize={12}
                                    height={24}
                                    tick={{ fill: "hsl(var(--muted-foreground))" }}
                                    tickLine={false}
                                    axisLine={false}
                                    tickFormatter={(value: number) => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                />
                                <YAxis
                                    stroke="hsl(var(--muted-foreground))"
                                    fontSize={12}
                                    width={64}
                                    tick={{ fill: "hsl(var(--muted-foreground))" }}
                                    tickLine={false}
                                    axisLine={false}
                                    tickFormatter={(value: number) => formatBytes(value)}
                                />
                                <ChartTooltip
                                    content={
                                        <ChartTooltipContent
                                            labelFormatter={(_value, payload) => {
                                                const ts = payload?.[0]?.payload?.ts
                                                return ts ? new Date(ts).toLocaleTimeString() : ""
                                            }}
                                            formatter={bytesFormatter(trafficConfig)}
                                        />
                                    }
                                />
                                <Area
                                    type="monotone"
                                    dataKey="bytesIn"
                                    stroke="var(--color-bytesIn)"
                                    fill="var(--color-bytesIn)"
                                    fillOpacity={0.25}
                                    isAnimationActive={false}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="bytesOut"
                                    stroke="var(--color-bytesOut)"
                                    fill="var(--color-bytesOut)"
                                    fillOpacity={0.2}
                                    isAnimationActive={false}
                                />
                            </AreaChart>
                        </ChartContainer>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Protocol Split</CardTitle>
                    </CardHeader>
                    <CardContent className="h-[280px]">
                        <ChartContainer config={protocolConfig} className="aspect-auto h-full w-full">
                            <PieChart>
                                <Pie data={protocolData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={90} isAnimationActive={false}>
                                    {protocolData.map((entry, index) => (
                                        <Cell key={`${entry.name}-${index}`} fill={index % 2 === 0 ? "#c4b5fd" : "#fdba74"} />
                                    ))}
                                </Pie>
                                <ChartTooltip content={<ChartTooltipContent />} />
                            </PieChart>
                        </ChartContainer>
                    </CardContent>
                </Card>
            </section>

            <section className="grid gap-4 lg:grid-cols-2">
                <Card>
                    <CardHeader>
                        <CardTitle>Top Talkers</CardTitle>
                    </CardHeader>
                    <CardContent className="h-[260px]">
                        <ChartContainer config={talkersConfig} className="aspect-auto h-full w-full">
                            <BarChart data={talkers} layout="vertical" margin={{ left: 16, right: 12 }}>
                                <XAxis type="number" hide />
                                <YAxis dataKey="label" type="category" width={200} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} />
                                <ChartTooltip
                                    content={
                                        <ChartTooltipContent
                                            labelFormatter={(_label, payload) =>
                                                payload?.[0]?.payload?.tooltip ? payload[0].payload.tooltip : String(_label)
                                            }
                                            formatter={bytesFormatter(talkersConfig)}
                                        />
                                    }
                                />
                                <Bar dataKey="bytes" fill="var(--color-bytes)" radius={6} isAnimationActive={false} />
                            </BarChart>
                        </ChartContainer>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader>
                        <CardTitle>Top Container Talkers</CardTitle>
                    </CardHeader>
                    <CardContent className="h-[260px]">
                        <ChartContainer config={containerConfig} className="aspect-auto h-full w-full">
                            <BarChart data={containerTalkers} layout="vertical" margin={{ left: 16, right: 12 }}>
                                <XAxis type="number" hide />
                                <YAxis dataKey="name" type="category" width={160} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} />
                                <ChartTooltip
                                    content={
                                        <ChartTooltipContent
                                            formatter={bytesFormatter(containerConfig)}
                                        />
                                    }
                                />
                                <Bar dataKey="bytes" fill="var(--color-bytes)" radius={6} isAnimationActive={false} />
                            </BarChart>
                        </ChartContainer>
                    </CardContent>
                </Card>
            </section>

            <section className="grid gap-4">
                <Card>
                    <CardHeader>
                        <CardTitle>Per-interface Breakdown</CardTitle>
                    </CardHeader>
                    <CardContent className="h-[260px]">
                        <ChartContainer config={interfaceConfig} className="aspect-auto h-full w-full">
                            <BarChart data={interfaceData} margin={{ left: 12, right: 12 }}>
                                <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                                <YAxis
                                    stroke="hsl(var(--muted-foreground))"
                                    fontSize={12}
                                    tickLine={false}
                                    axisLine={false}
                                    tickFormatter={(value: number) => formatBytes(value)}
                                />
                                <ChartTooltip
                                    content={
                                        <ChartTooltipContent
                                            formatter={bytesFormatter(interfaceConfig)}
                                        />
                                    }
                                />
                                <Bar dataKey="bytesIn" stackId="a" fill="var(--color-bytesIn)" radius={[6, 6, 0, 0]} isAnimationActive={false} />
                                <Bar dataKey="bytesOut" stackId="a" fill="var(--color-bytesOut)" radius={[6, 6, 0, 0]} isAnimationActive={false} />
                            </BarChart>
                        </ChartContainer>
                    </CardContent>
                </Card>
            </section>
        </div>
    )
})
