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
