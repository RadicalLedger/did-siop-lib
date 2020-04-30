export function leftpad(data: any, size: number = 64) {
    if (data.length === size) return data
    return '0'.repeat(size - data.length) + data
}