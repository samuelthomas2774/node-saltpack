
import SignedMessageHeader from './header';
import SignedMessagePayload from './payload';
import {chunkBuffer} from '../util';
import {Transform, Readable, TransformCallback} from 'stream';
import * as tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';
import {DataViewIndexOutOfBoundsError} from '@msgpack/msgpack/dist/Decoder';

export let debug = false;

export const CHUNK_LENGTH = 1024 * 1024;

export function sign(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair): Buffer {
    const chunks = chunkBuffer(data, CHUNK_LENGTH);

    const header = SignedMessageHeader.create(keypair.publicKey, true);
    const payloads = [];

    for (const i in chunks) {
        const chunk = chunks[i];
        const final = chunks.length === (parseInt(i) + 1);
        const payload = SignedMessagePayload.create(header, keypair.secretKey, chunk, BigInt(i), final);

        payloads.push(payload);
    }

    return Buffer.concat([
        header.encoded,
        Buffer.concat(payloads.map(payload => payload.encoded)),
    ]);
}

export class SignStream extends Transform {
    readonly header: SignedMessageHeader;
    private in_buffer = Buffer.alloc(0);
    private payload_index = BigInt(0);

    constructor(readonly keypair: tweetnacl.SignKeyPair) {
        super();

        this.header = SignedMessageHeader.create(keypair.publicKey, true);
        this.push(this.header.encoded);
    }

    _transform(data: Buffer, encoding: string, callback: TransformCallback) {
        if (debug) console.log('Processing chunk #d: %s', -1, data);

        this.in_buffer = Buffer.concat([this.in_buffer, data]);

        while (this.in_buffer.length > CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);

            // This is never the final payload as there must be additional data in `in_buffer`

            const payload = SignedMessagePayload.create(
                this.header, this.keypair.secretKey, chunk, this.payload_index, /* final */ false
            );

            this.push(payload.encoded);
            this.payload_index++;
        }

        callback();
    }

    _flush(callback: TransformCallback) {
        while (this.in_buffer.length >= CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);

            const final = !this.in_buffer.length;
            const payload = SignedMessagePayload.create(
                this.header, this.keypair.secretKey, chunk, this.payload_index, final
            );

            this.push(payload.encoded);
            this.payload_index++;
        }

        if (this.in_buffer.length) {
            const chunk = this.in_buffer;
            this.in_buffer = Buffer.alloc(0);

            const final = !this.in_buffer.length;
            const payload = SignedMessagePayload.create(
                this.header, this.keypair.secretKey, chunk, this.payload_index, final
            );

            this.push(payload.encoded);
            this.payload_index++;
        }

        callback();
    }
}

export async function verify(signed: Uint8Array, public_key: Uint8Array): Promise<Buffer> {
    const stream = new Readable();
    stream.push(signed);
    stream.push(null);

    const items = [];

    for await (const item of msgpack.decodeStream(stream)) {
        items.push(item);
    }

    const header_data = items.shift() as any;
    const header = SignedMessageHeader.decode(header_data, true);

    let output = Buffer.alloc(0);

    for (const i in items) {
        const message = items[i];
        const final = items.length === (parseInt(i) + 1);

        const payload = SignedMessagePayload.decode(message, true);
        payload.verify(header, public_key, BigInt(i));

        if (payload.final && !final) {
            throw new Error('Found payload with invalid final flag, message extended?');
        }
        if (!payload.final && final) {
            throw new Error('Found payload with invalid final flag, message truncated?');
        }

        output = Buffer.concat([output, payload.data]);
    }

    if (!items.length) {
        throw new Error('No signed payloads, message truncated?');
    }

    return output;
}

export class VerifyStream extends Transform {
    private decoder = new msgpack.Decoder(undefined!, undefined);
    private header_data: SignedMessageHeader | null = null;
    private last_payload: SignedMessagePayload | null = null;
    private payload_index = BigInt(-1);
    private i = 0;

    constructor(readonly public_key: Uint8Array) {
        super();
    }

    get header() {
        if (!this.header_data) throw new Error('Header hasn\'t been decoded yet');
        return this.header_data;
    }

    _transform(data: Buffer, encoding: string, callback: TransformCallback) {
        this.decoder.appendBuffer(data);

        try {
            let message;
            while (message = this.decoder.decodeSync()) {
                const remaining = Buffer.from(this.decoder.bytes).slice(this.decoder.pos);
                this.decoder.setBuffer(remaining);

                this._handleMessage(message);
            }
        } catch (err) {
            if (!(err instanceof DataViewIndexOutOfBoundsError)) {
                return callback(err);
            }
        }

        callback();
    }

    private _handleMessage(data: unknown) {
        if (debug) console.log('Processing chunk #%d: %O', this.i++, data);

        if (!this.header_data) {
            const header = SignedMessageHeader.decode(data as any, true);

            this.header_data = header;
        } else {
            this.payload_index++;

            if (this.last_payload) {
                if (this.last_payload.final) {
                    const err = new Error('Found payload with invalid final flag, message extended?');
                    this.emit('error', err);
                    throw err;
                }

                this.push(this.last_payload.data);
            }

            const payload = SignedMessagePayload.decode(data, true);
            payload.verify(this.header, this.public_key, this.payload_index);

            this.last_payload = payload;
        }
    }

    _flush(callback: TransformCallback) {
        try {
            if (this.last_payload) {
                if (!this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message truncated?');
                }

                this.push(this.last_payload.data);
            }

            if (!this.last_payload) {
                throw new Error('No signed payloads, message truncated?');
            }
        } catch (err) {
            return callback(err);
        }

        callback();
    }
}

export function signDetached(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair): Buffer {
    const header = SignedMessageHeader.create(keypair.publicKey, false);

    return Buffer.concat([
        header.encoded,
        msgpack.encode(header.signDetached(Buffer.from(data), keypair.secretKey)),
    ]);
}

export async function verifyDetached(signature: Uint8Array, data: Uint8Array | string, public_key: Uint8Array) {
    const stream = new Readable();
    stream.push(signature);
    stream.push(null);

    const items = [];

    for await (const item of msgpack.decodeStream(stream)) {
        items.push(item);
    }

    const [header_data, signature_data]: any = items;

    const header = SignedMessageHeader.decode(header_data, true);

    header.verifyDetached(signature_data, Buffer.from(data), public_key);
}
