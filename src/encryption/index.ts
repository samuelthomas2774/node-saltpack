
import EncryptedMessageHeader from './header';
import EncryptedMessageRecipient from './recipient';
import EncryptedMessagePayload from './payload';
import {chunkBuffer} from '../util';
import {Readable, Transform, TransformCallback} from 'stream';
import * as crypto from 'crypto';
import * as util from 'util';
import * as tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';
import {DataViewIndexOutOfBoundsError} from '@msgpack/msgpack/dist/Decoder';

const randomBytes = util.promisify(crypto.randomBytes);

const CHUNK_LENGTH = 1024 * 1024;

export let debug = false;
export let debug_fix_key: Buffer | null = null;
export let debug_fix_keypair: tweetnacl.BoxKeyPair | null = null;

export async function encrypt(
    data: Uint8Array | string, keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[]
): Promise<Buffer> {
    const chunks = chunkBuffer(data, CHUNK_LENGTH);

    // 1. Generate a random 32-byte payload key.
    const payload_key = debug_fix_key ?? await randomBytes(32);

    // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
    const ephemeral_keypair = debug_fix_keypair ?? tweetnacl.box.keyPair();

    keypair = keypair ?? ephemeral_keypair;

    const recipients = recipients_keys.map((key, index) => {
        return EncryptedMessageRecipient.create(key, ephemeral_keypair.secretKey, payload_key, index);
    });

    const header = EncryptedMessageHeader.create(ephemeral_keypair.publicKey, payload_key, keypair.publicKey, recipients);

    for (const recipient of recipients) {
        recipient.generateMacKeyForSender(header.hash, ephemeral_keypair.secretKey, keypair.secretKey);
    }

    const payloads = [];

    for (const i in chunks) {
        const chunk = chunks[i];
        const final = chunks.length === (parseInt(i) + 1);
        const payload = EncryptedMessagePayload.create(header, payload_key, chunk, BigInt(i), final);

        payloads.push(payload);
    }

    return Buffer.concat([
        header.encoded,
        Buffer.concat(payloads.map(payload => payload.encoded)),
    ]);
}

export class EncryptStream extends Transform {
    readonly payload_key: Buffer;
    readonly ephemeral_keypair: tweetnacl.BoxKeyPair;
    readonly keypair: tweetnacl.BoxKeyPair;
    readonly header: EncryptedMessageHeader;
    private in_buffer = Buffer.alloc(0);
    private payload_index = BigInt(0);
    private i = 0;

    constructor(keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[]) {
        super();

        // 1. Generate a random 32-byte payload key.
        this.payload_key = debug_fix_key ?? crypto.randomBytes(32);

        // 2. Generate a random ephemeral keypair, using crypto_box_keypair.
        this.ephemeral_keypair = debug_fix_keypair ?? tweetnacl.box.keyPair();

        this.keypair = keypair ?? this.ephemeral_keypair;

        const recipients = recipients_keys.map((key, index) => {
            return EncryptedMessageRecipient.create(key, this.ephemeral_keypair.secretKey, this.payload_key, index);
        });

        this.header = EncryptedMessageHeader.create(
            this.ephemeral_keypair.publicKey, this.payload_key, this.keypair.publicKey, recipients
        );

        this.push(this.header.encoded);

        for (const recipient of recipients) {
            recipient.generateMacKeyForSender(
                this.header.hash, this.ephemeral_keypair.secretKey, this.keypair.secretKey
            );
        }
    }

    _transform(data: Buffer, encoding: string, callback: TransformCallback) {
        if (debug) console.log('Processing chunk #%d: %s', this.i++, data);

        this.in_buffer = Buffer.concat([this.in_buffer, data]);

        while (this.in_buffer.length > CHUNK_LENGTH) {
            const chunk = this.in_buffer.slice(0, CHUNK_LENGTH);
            this.in_buffer = this.in_buffer.slice(CHUNK_LENGTH);

            // This is never the final payload as there must be additional data in `in_buffer`

            const payload = EncryptedMessagePayload.create(
                this.header, this.payload_key, chunk, this.payload_index, /* final */ false
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
            const payload = EncryptedMessagePayload.create(
                this.header, this.payload_key, chunk, this.payload_index, final
            );

            this.push(payload.encoded);
            this.payload_index++;
        }

        if (this.in_buffer.length) {
            const chunk = this.in_buffer;
            this.in_buffer = Buffer.alloc(0);

            const final = !this.in_buffer.length;
            const payload = EncryptedMessagePayload.create(
                this.header, this.payload_key, chunk, this.payload_index, final
            );

            this.push(payload.encoded);
            this.payload_index++;
        }

        callback();
    }
}

export interface DecryptResult extends Buffer {
    sender_public_key: Uint8Array | null;
}

export async function decrypt(encrypted: Uint8Array, keypair: tweetnacl.BoxKeyPair): Promise<DecryptResult> {
    const stream = new Readable();
    stream.push(encrypted);
    stream.push(null);

    const items = [];

    for await (const item of msgpack.decodeStream(stream)) {
        items.push(item);
    }

    const header_data = items.shift() as any;
    const header = EncryptedMessageHeader.decode(header_data, true);

    const [payload_key, recipient] = header.decryptPayloadKey(keypair);
    const sender_public_key = header.decryptSender(payload_key);

    recipient.generateMacKeyForRecipient(header.hash, header.public_key, sender_public_key, keypair.secretKey);

    let output = Buffer.alloc(0);

    for (const i in items) {
        const message = items[i];
        const payload = EncryptedMessagePayload.decode(message, true);

        const final = items.length === (parseInt(i) + 1);
        if (payload.final && !final) {
            throw new Error('Found payload with invalid final flag, message extended?');
        }
        if (!payload.final && final) {
            throw new Error('Found payload with invalid final flag, message truncated?');
        }

        output = Buffer.concat([output, payload.decrypt(header, recipient, payload_key, BigInt(i))]);
    }

    if (!items.length) {
        throw new Error('No encrypted payloads, message truncated?');
    }

    return Object.assign(output, {
        sender_public_key,
    });
}

export class DecryptStream extends Transform {
    private decoder = new msgpack.Decoder(undefined!, undefined);
    private header_data: [EncryptedMessageHeader, Uint8Array, EncryptedMessageRecipient, Uint8Array] | null = null;
    private last_payload: EncryptedMessagePayload | null = null;
    private payload_index = BigInt(-1);
    private i = 0;

    constructor(readonly keypair: tweetnacl.BoxKeyPair) {
        super();
    }

    get header() {
        if (!this.header_data) throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[0];
    }
    get payload_key() {
        if (!this.header_data) throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[1];
    }
    get recipient() {
        if (!this.header_data) throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[2];
    }
    get sender_public_key() {
        if (!this.header_data) throw new Error('Header hasn\'t been decoded yet');
        return this.header_data[3];
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
        if (debug) console.log('Processing chunk #%d: %s', this.i++, data);

        if (!this.header_data) {
            const header = EncryptedMessageHeader.decode(data as any, true);

            const [payload_key, recipient] = header.decryptPayloadKey(this.keypair);
            const sender_public_key = header.decryptSender(payload_key);

            recipient.generateMacKeyForRecipient(
                header.hash, header.public_key, sender_public_key, this.keypair.secretKey
            );

            this.header_data = [header, payload_key, recipient, sender_public_key];
        } else {
            this.payload_index++;

            if (this.last_payload) {
                if (this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message extended?');
                }

                this.push(this.last_payload.decrypt(
                    this.header, this.recipient, this.payload_key, this.payload_index - BigInt(1)
                ));
            }

            const payload = EncryptedMessagePayload.decode(data, true);
            this.last_payload = payload;
        }
    }

    _flush(callback: TransformCallback) {
        try {
            if (this.last_payload) {
                if (!this.last_payload.final) {
                    throw new Error('Found payload with invalid final flag, message truncated?');
                }

                this.push(this.last_payload.decrypt(this.header, this.recipient, this.payload_key, this.payload_index));
            }

            if (!this.last_payload) {
                throw new Error('No encrypted payloads, message truncated?');
            }
        } catch (err) {
            return callback(err);
        }

        callback();
    }
}
