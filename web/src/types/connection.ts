export type ContainerInfo = {
  id: string
  name: string
  image: string
  pid: number
}

export type Connection = {
  packets: number
  bytes: number
  saddr: string
  addr: string
  ifindex: number
  ifname: string
  cgroupId: number
  direction: number
  proto: number
  sHost: string[]
  dHost: string[]
  container?: ContainerInfo
  type: number
}

export type InterfaceSummary = {
  connections: number
  bytesIn: number
  bytesOut: number
  packetsIn: number
  packetsOut: number
}

export type Talker = {
  addr: string
  bytes: number
}

export type ContainerSummary = {
  id: string
  name: string
  image: string
  pid: number
  connections: number
  bytesIn: number
  bytesOut: number
  packetsIn: number
  packetsOut: number
  topDestinations: Talker[]
}

export type HistorySummary = {
  totalConnections: number
  bytesIn: number
  bytesOut: number
  packetsIn: number
  packetsOut: number
  uniqueSrcIps: number
  uniqueDstIps: number
  perInterface: Record<string, InterfaceSummary>
  perProtocol: Record<string, number>
  topTalkers: Talker[]
  perContainer: Record<string, ContainerSummary>
}

export type Snapshot = {
  timestamp: number
  summary: HistorySummary
}

export type ConnectionsResponse = {
  data: Connection[]
  total: number
}
