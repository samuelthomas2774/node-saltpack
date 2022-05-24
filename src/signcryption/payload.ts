
import SigncryptedMessageHeader from './header.js';
import * as crypto from 'crypto';
import tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';

// [
//     signcrypted chunk,
//     final flag,
// ]

export default class SigncryptedMessagePayload {
    static readonly PAYLOAD_NONCE_PREFIX = Buffer.from('saltpack_ploadsb');

    /** The NaCl secretbox for this payload */
    readonly payload_secretbox: Uint8Array;
    /** `true` if this is the final payload */
    readonly final: boolean;

    constructor(payload_secretbox: Uint8Array, final: boolean) {
        this.payload_secretbox = payload_secretbox;
        this.final = final;
    }

    get encoded_data(): Buffer {
        return Object.defineProperty(this, 'encoded_data', {
            value: this.encode(),
        }).encoded_data;
    }

    /** The MessagePack encoded payload data */
    get encoded() {
        return this.encoded_data;
    }

    static create(
        header: SigncryptedMessageHeader, payload_key: Uint8Array, private_key: Uint8Array | null,
        data: Buffer, index: bigint, final = false
    ): SigncryptedMessagePayload {
        const nonce = this.generateNonce(header.hash, index, final);

        // 3. Sign the signature input with the sender's long-term private signing key, producing a 64-byte
        // Ed25519 signature. If the sender is anonymous, the signature is 64 zero bytes instead.
        const signature = private_key ?
            tweetnacl.sign.detached(
                Uint8Array.from(this.generateSignatureData(header.hash, nonce, final, data)),
                Uint8Array.from(private_key),
            ) :
            Buffer.alloc(64);

        // 4. Prepend that signature onto the front of the plaintext chunk.
        // 5. Encrypt the attached signature from #4 using the payload key and the packet nonce.

        const payload_secretbox = Buffer.from(tweetnacl.secretbox(
            Uint8Array.from(Buffer.concat([signature, data])),
            Uint8Array.from(nonce),
            Uint8Array.from(payload_key),
        ));

        return new this(payload_secretbox, final);
    }

    static generateNonce(header_hash: Uint8Array, index: bigint, final: boolean) {
        // 1. Compute the packet nonce. Take the first 16 bytes of the header hash. If this is the final packet,
        // set the least significant bit of the last of those bytes to one (nonce[15] |= 0x01), otherwise set it
        // to zero (nonce[15] &= 0xfe). Finally, append the 8-byte unsigned big-endian packet number, where the
        // first payload packet is zero.

        const nonce = Buffer.alloc(24, Buffer.from(header_hash));
        nonce[15] = final ? nonce[15] | 0x01 : nonce[15] & 0xfe;
        nonce.writeBigUInt64BE(index, 16);

        return nonce;
    }

    static generateSignatureData(
        header_hash: Uint8Array, nonce: Uint8Array, final: boolean, data: Uint8Array
    ) {
        // 2. Concatenate several values to form the signature input:
        //     - the constant string saltpack encrypted signature
        //     - a null byte, 0x00
        //     - the header hash
        //     - the packet nonce computed above
        //     - the final flag byte, 0x00 for false and 0x01 for true
        //     - the SHA512 hash of the plaintext

        return Buffer.concat([
            Buffer.from('saltpack encrypted signature'),
            Buffer.from([0x00]),
            header_hash,
            nonce,
            Buffer.from([final ? 0x01 : 0x00]),
            crypto.createHash('sha512').update(data).digest(),
        ]);
    }

    encode() {
        return SigncryptedMessagePayload.encodePayload(this.payload_secretbox, this.final);
    }

    static encodePayload(payload_secretbox: Uint8Array, final: boolean): Buffer {
        const data = [
            payload_secretbox,
            final,
        ];

        return Buffer.from(msgpack.encode(data));
    }

    static decode(encoded: any, unpacked = false): SigncryptedMessagePayload {
        const data = unpacked ? encoded : msgpack.decode(encoded) as any;

        if (data.length < 2) throw new Error('Invalid data');

        const [payload_secretbox, final] = data;

        return new this(payload_secretbox, final);
    }

    decrypt(
        header: SigncryptedMessageHeader, public_key: Uint8Array | null, payload_key: Uint8Array, index: bigint
    ) {
        // 1. Compute the packet nonce as above.
        const nonce = SigncryptedMessagePayload.generateNonce(header.hash, index, this.final);

        // 2. Decrypt the chunk using the payload key and the packet nonce.
        const signature_data = tweetnacl.secretbox.open(
            Uint8Array.from(this.payload_secretbox),
            Uint8Array.from(nonce),
            Uint8Array.from(payload_key),
        );

        if (!signature_data) {
            throw new Error('Failed to decrypt data');
        }

        // 3. Take the first 64 bytes of the plaintext as the detached signature, and the rest as the payload chunk.
        const data = signature_data.slice(64);

        if (public_key) {
            const signature = signature_data.slice(0, 64);

            // 4. Compute the signature input as above.
            const sign_data = SigncryptedMessagePayload.generateSignatureData(header.hash, nonce, this.final, data);

            // 5. Verify the detached signature from step #3 against the signature input. If the sender's public key
            // is all zero bytes, however, then the sender is anonymous, and verification is skipped.
            if (!tweetnacl.sign.detached.verify(
                Uint8Array.from(sign_data),
                Uint8Array.from(signature),
                Uint8Array.from(public_key),
            )) {
                throw new Error('Invalid signature');
            }
        }

        // 6. If the signature was valid, output the payload chunk.
        return data;
    }
}
