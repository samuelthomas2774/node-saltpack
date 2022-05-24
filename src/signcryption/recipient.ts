
import * as crypto from 'crypto';
import tweetnacl from 'tweetnacl';
import { isBufferOrUint8Array } from '../util';

export default class SigncryptedMessageRecipient {
    static readonly SHARED_KEY_NONCE = Buffer.from('saltpack_derived_sboxkey');
    static readonly HMAC_KEY = Buffer.from('saltpack signcryption box key identifier');
    static readonly PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 = Buffer.from('saltpack_recipsb');

    readonly recipient_identifier: Uint8Array;
    // readonly shared_symmetric_key: Uint8Array | null;
    /** The NaCl secretbox containing the payload key for this recipient */
    readonly encrypted_payload_key: Uint8Array;
    /** The recipient index, starting from zero */
    readonly index: bigint;
    /** The nonce for `encrypted_payload_key` */
    readonly recipient_index: Buffer;

    constructor(
        recipient_identifier: Uint8Array, /*shared_symmetric_key: Uint8Array | null,*/
        encrypted_payload_key: Uint8Array, index: bigint
    ) {
        if (!isBufferOrUint8Array(recipient_identifier) || recipient_identifier.length !== 32) {
            throw new TypeError('recipient_identifier must be a 32 byte Uint8Array');
        }
        if (!isBufferOrUint8Array(encrypted_payload_key) || encrypted_payload_key.length !== 48) {
            throw new TypeError('payload_key_box must be a 48 byte Uint8Array');
        }
        if (typeof index !== 'bigint') {
            throw new TypeError('index must be a bigint');
        }

        this.recipient_identifier = recipient_identifier;
        // this.shared_symmetric_key = shared_symmetric_key;
        this.encrypted_payload_key = encrypted_payload_key;
        this.index = index;
        this.recipient_index = SigncryptedMessageRecipient.generateRecipientIndex(index);
    }

    static create(
        public_key: Uint8Array, ephemeral_private_key: Uint8Array, payload_key: Uint8Array, index: number | bigint
    ): SigncryptedMessageRecipient {
        if (typeof index === 'number') index = BigInt(index);

        const recipient_index = this.generateRecipientIndex(index);

        const {shared_symmetric_key, recipient_identifier} =
            this.generateRecipientIdentifierForSender(public_key, ephemeral_private_key, recipient_index);

        // Secretbox the payload key using this derived symmetric key, with the nonce saltpack_recipsbXXXXXXXX,
        // where XXXXXXXX is the 8-byte big-endian unsigned recipient index.
        const encrypted_payload_key = tweetnacl.secretbox(
            Uint8Array.from(payload_key),
            Uint8Array.from(recipient_index),
            Uint8Array.from(shared_symmetric_key),
        );

        return new this(recipient_identifier, /*shared_symmetric_key,*/ encrypted_payload_key, index);
    }

    static from(
        recipient_identifier: Uint8Array, encrypted_payload_key: Uint8Array, index: number | bigint
    ): SigncryptedMessageRecipient {
        if (typeof index === 'number') index = BigInt(index);

        return new this(recipient_identifier, /*null,*/ encrypted_payload_key, index);
    }

    static generateRecipientIndex(index: bigint): Buffer {
        const buffer = Buffer.alloc(8);
        buffer.writeBigUInt64BE(index);
        return Buffer.concat([this.PAYLOAD_KEY_BOX_NONCE_PREFIX_V2, buffer]);
    }

    /**
     * Decrypts the payload key.
     */
    decryptPayloadKey(shared_symmetric_key: Uint8Array): Uint8Array | null {
        return tweetnacl.secretbox.open(
            Uint8Array.from(this.encrypted_payload_key),
            Uint8Array.from(this.recipient_index),
            Uint8Array.from(shared_symmetric_key),
        );
    }

    static generateRecipientIdentifierForSender(
        public_key: Uint8Array, ephemeral_private_key: Uint8Array, recipient_index: Uint8Array
    ) {
        // For Curve25519 recipient public keys, first derive a shared symmetric key by boxing 32 zero bytes with
        // the recipient public key, the ephemeral private key, and the nonce saltpack_derived_sboxkey, and taking
        // the last 32 bytes of the resulting box.
        const shared_symmetric_key = Buffer.from(tweetnacl.box(
            Uint8Array.from(Buffer.alloc(32).fill('\0')),
            Uint8Array.from(this.SHARED_KEY_NONCE),
            Uint8Array.from(public_key),
            Uint8Array.from(ephemeral_private_key),
        )).slice(-32);

        // To compute the recipient identifier, concatenate the derived symmetric key and the
        // saltpack_recipsbXXXXXXXX nonce together, and HMAC-SHA512 them under the key saltpack signcryption box
        // key identifier. The identifier is the first 32 bytes of that HMAC.
        const recipient_identifier = crypto.createHmac('sha512', this.HMAC_KEY)
            .update(shared_symmetric_key)
            .update(recipient_index)
            .digest().slice(0, 32);

        return {shared_symmetric_key, recipient_identifier};
    }

    static generateRecipientIdentifierForRecipient(
        ephemeral_public_key: Uint8Array, private_key: Uint8Array, recipient_index: Uint8Array
    ) {
        // For Curve25519 recipient public keys, first derive a shared symmetric key by boxing 32 zero bytes with
        // the recipient public key, the ephemeral private key, and the nonce saltpack_derived_sboxkey, and taking
        // the last 32 bytes of the resulting box.
        const shared_symmetric_key = Buffer.from(tweetnacl.box(
            Uint8Array.from(Buffer.alloc(32).fill('\0')),
            Uint8Array.from(this.SHARED_KEY_NONCE),
            Uint8Array.from(ephemeral_public_key),
            Uint8Array.from(private_key),
        )).slice(-32);

        // To compute the recipient identifier, concatenate the derived symmetric key and the
        // saltpack_recipsbXXXXXXXX nonce together, and HMAC-SHA512 them under the key saltpack signcryption box
        // key identifier. The identifier is the first 32 bytes of that HMAC.
        const recipient_identifier = crypto.createHmac('sha512', this.HMAC_KEY)
            .update(shared_symmetric_key)
            .update(recipient_index)
            .digest().slice(0, 32);

        return {shared_symmetric_key, recipient_identifier};
    }
}
