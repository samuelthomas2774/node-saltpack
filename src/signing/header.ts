
import Header, {MessageType} from '../message-header';
import * as crypto from 'crypto';
import * as tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';

// [
//     format name,
//     version,
//     mode,
//     sender public key,
//     nonce,
// ]

export default class SignedMessageHeader extends Header {
    static readonly DETACHED_SIGNATURE_PREFIX = Buffer.from('saltpack detached signature\0');

    static debug_fix_nonce: Buffer | null = null;

    /** The sender's Ed25519 public key */
    readonly public_key: Uint8Array;
    /** Random data for this message */
    readonly nonce: Uint8Array;
    /** `true` if this is an attached signature header, `false` if this is a detached signature header */
    readonly attached: boolean;
    private _encoded_data: [Buffer, Buffer] | null = null;

    constructor(public_key: Uint8Array, nonce: Uint8Array, attached = true) {
        super();
        this.public_key = public_key;
        this.nonce = nonce;
        this.attached = attached;
    }

    get encoded_data(): [Buffer, Buffer] {
        return Object.defineProperty(this, '_encoded_data', {
            value: this.encode(),
        })._encoded_data;
    }

    /** The MessagePack encoded outer header data */
    get encoded() {
        return this.encoded_data[1];
    }
    /** The SHA512 hash of the MessagePack encoded inner header data */
    get hash() {
        return this.encoded_data[0];
    }

    static create(public_key: Uint8Array, attached = true): SignedMessageHeader {
        const nonce = this.debug_fix_nonce ?? crypto.randomBytes(32);

        return new this(public_key, nonce, attached);
    }

    encode() {
        return SignedMessageHeader.encodeHeader(this.public_key, this.nonce, this.attached);
    }

    static encodeHeader(public_key: Uint8Array, nonce: Uint8Array, attached: boolean): [Buffer, Buffer] {
        const data = [
            'saltpack',
            [2, 0],
            attached ? MessageType.ATTACHED_SIGNING : MessageType.DETACHED_SIGNING,
            public_key,
            nonce,
        ];

        const encoded = msgpack.encode(data);

        const header_hash = crypto.createHash('sha512').update(encoded).digest();

        return [header_hash, Buffer.from(msgpack.encode(encoded))];
    }

    static decode(encoded: Uint8Array, unwrapped = false) {
        const [header_hash, data] = super.decode1(encoded, unwrapped);

        if (data[2] !== MessageType.ATTACHED_SIGNING &&
            data[2] !== MessageType.DETACHED_SIGNING) throw new Error('Invalid data');

        if (data.length < 5) throw new Error('Invalid data');

        const [,,, public_key, nonce] = data;

        return new this(public_key, nonce, data[2] === MessageType.ATTACHED_SIGNING);
    }

    signDetached(data: Uint8Array, private_key: Uint8Array): Buffer {
        if (this.attached) {
            throw new Error('Header attached is true');
        }

        const hash = crypto.createHash('sha512')
            .update(this.hash)
            .update(data)
            .digest();

        const sign_data = Buffer.concat([SignedMessageHeader.DETACHED_SIGNATURE_PREFIX, hash]);

        return Buffer.from(tweetnacl.sign.detached(sign_data, private_key));
    }

    verifyDetached(signature: Uint8Array, data: Uint8Array, public_key: Uint8Array) {
        if (this.attached) {
            throw new Error('Header attached is true');
        }

        const hash = crypto.createHash('sha512')
            .update(this.hash)
            .update(data)
            .digest();

        const sign_data = Buffer.concat([SignedMessageHeader.DETACHED_SIGNATURE_PREFIX, hash]);

        if (!tweetnacl.sign.detached.verify(sign_data, signature, public_key)) {
            throw new Error('Invalid signature');
        }
    }
}
