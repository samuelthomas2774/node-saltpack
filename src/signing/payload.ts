
import SignedMessageHeader from './header';
import * as crypto from 'crypto';
import * as tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';

// [
//     final flag,
//     signature,
//     payload chunk,
// ]

export default class SignedMessagePayload {
    static readonly PAYLOAD_SIGNATURE_PREFIX = Buffer.from('saltpack attached signature\0');

    /** `true` if this is the final payload */
    readonly final: boolean;
    /** The NaCl detached signature for this payload */
    readonly signature: Buffer;
    /** This payload's data */
    readonly data: Buffer;
    private _encoded_data: Buffer | null = null;

    constructor(final: boolean, signature: Buffer, data: Buffer) {
        this.final = final;
        this.signature = signature;
        this.data = data;
    }

    get encoded_data(): Buffer {
        return Object.defineProperty(this, '_encoded_data', {
            value: this.encode(),
        })._encoded_data;
    }

    /** The MessagePack encoded payload data */
    get encoded() {
        return this.encoded_data;
    }

    static create(
        header: SignedMessageHeader, private_key: Uint8Array, data: Buffer, index: number | bigint, final = false
    ): SignedMessagePayload {
        if (!(private_key instanceof Buffer)) private_key = Buffer.from(private_key);
        if (typeof index === 'number') index = BigInt(index);

        const sign_data = this.generateSignData(header.hash, index, final, data);
        const signature = tweetnacl.sign.detached(sign_data, private_key);

        return new this(final, Buffer.from(signature), data);
    }

    static generateSignData(header_hash: Buffer, index: bigint, final: boolean, data: Buffer): Buffer {
        // To make each signature, the sender first takes the SHA512 hash of the concatenation of four values:

        // the header hash from above
        // the packet sequence number, as a 64-bit big-endian unsigned integer, where the first payload packet is zero
        // the final flag, a 0x00 byte for false and a 0x01 byte for true
        // the payload chunk

        const index_buffer = Buffer.alloc(8);
        index_buffer.writeBigUInt64BE(index);

        return Buffer.concat([
            this.PAYLOAD_SIGNATURE_PREFIX,
            crypto.createHash('sha512')
                .update(header_hash)
                .update(index_buffer)
                .update(final ? '\x01' : '\x00')
                .update(data)
                .digest(),
        ]);
    }

    encode() {
        return SignedMessagePayload.encodePayload(this.final, this.signature, this.data);
    }

    static encodePayload(final: boolean, signature: Buffer, payload_chunk: Buffer): Buffer {
        return Buffer.from(msgpack.encode([
            final,
            signature,
            payload_chunk,
        ]));
    }

    static decode(encoded: any, unpacked = false): SignedMessagePayload {
        const data = unpacked ? encoded : msgpack.decode(encoded) as any;

        if (data.length < 3) throw new Error('Invalid data');

        const [final, signature, payload_chunk] = data;

        return new this(final, signature, payload_chunk);
    }

    verify(header: SignedMessageHeader, public_key: Uint8Array, index: bigint) {
        const sign_data = SignedMessagePayload.generateSignData(header.hash, index, this.final, this.data);

        if (!tweetnacl.sign.detached.verify(sign_data, this.signature, public_key)) {
            throw new Error('Invalid signature');
        }
    }
}
