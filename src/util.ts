
export function isBufferOrUint8Array(buffer: Buffer | Uint8Array) {
    return buffer instanceof Buffer || buffer instanceof Uint8Array;
}

export function chunkBuffer(buffer: Uint8Array | string, length: number): Buffer[]
export function chunkBuffer(_buffer: Uint8Array | string, length: number): Buffer[] {
    let buffer = _buffer instanceof Buffer ? _buffer : Buffer.from(_buffer);
    const result: Buffer[] = [];

    while (buffer.length > length) {
        const chunk = buffer.slice(0, length);
        buffer = buffer.slice(length);
        result.push(chunk);
    }

    if (buffer.length) {
        result.push(buffer);
    }

    return result;
}

export function chunkString(string: string, length: number): string[] {
    const result: string[] = [];

    while (string.length > length) {
        const chunk = string.substr(0, length);
        string = string.substr(length);
        result.push(chunk);
    }

    if (string.length) {
        result.push(string);
    }

    return result;
}
