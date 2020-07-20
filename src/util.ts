import {Transform, TransformCallback, Duplex} from 'stream';
import pump = require('pump');

export class MultiTransform extends Transform {
    static constructors: Function[] = [];
    streams: Transform[];
    pump: Duplex;

    constructor(..._args: any[]) {
        super();

        // @ts-ignore
        this.streams = this.constructor.constructors.map((constructor, index) => {
            const args = _args[index] instanceof Array ? _args[index] :
                index in _args ? [_args[index]] : [];

            const stream = constructor.prototype ?
                // @ts-ignore
                new constructor(...args) :
                constructor(...args);
            
            return stream;
        });

        // @ts-ignore
        this.pump = pump(this.streams);

        this.pump.on('error', err => this.emit('error', err));
        this.pump.on('finish', () => this.emit('finish'));
        this.pump.on('data', chunk => this.push(chunk));
    }

    static use(...constructors: Function[]): typeof MultiTransform {
        constructors = this.constructors.concat(constructors);

        return class extends this {
            static constructors = constructors;
        };
    }

    _transform(data: any, encoding: string, callback: TransformCallback) {
        this.pump.write(data, encoding, callback);
    }

    _flush(callback: TransformCallback) {
        this.pump.end(callback);
    }
}

export function chunkBuffer(buffer: Uint8Array | string, length: number): Buffer[]
export function chunkBuffer(_buffer: Uint8Array | string, length: number): Buffer[] {
    let buffer = _buffer instanceof Buffer ? _buffer : Buffer.from(_buffer);
    buffer = Buffer.from(buffer.toString());
    const result: Buffer[] = [];

    console.log(buffer, buffer.length, _buffer.toString().length);

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
