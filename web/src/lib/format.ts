export const formatBytes = (value: number) => {
    if (!Number.isFinite(value)) {
        return "0 B"
    }
    const units = ["B", "KB", "MB", "GB", "TB"]
    let size = Math.max(value, 0)
    let unitIndex = 0
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024
        unitIndex += 1
    }
    const precision = size >= 100 ? 0 : size >= 10 ? 1 : 2
    return `${size.toFixed(precision)} ${units[unitIndex]}`
}

export const formatCount = (value: number) => {
    if (!Number.isFinite(value)) {
        return "0"
    }
    return value.toLocaleString()
}

export const directionLabel = (direction: number) => {
    if (direction === 1) {
        return "ingress"
    }
    if (direction === 2) {
        return "egress"
    }
    return "unknown"
}

export const protocolLabel = (proto: number) => {
    if (proto === 6) {
        return "tcp"
    }
    if (proto === 17) {
        return "udp"
    }
    return "other"
}
