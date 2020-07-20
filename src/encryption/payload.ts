
import EncryptedMessageHeader from './header';
import EncryptedMessageRecipient from './recipient';
import * as crypto from 'crypto';
import * as tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';

// [
//     final flag,
//     authenticators list,
//     payload secretbox,
// ]

export default class EncryptedMessagePayload {
    static readonly PAYLOAD_NONCE_PREFIX = Buffer.from('saltpack_ploadsb');

    /** `true` if this is the final payload */
    readonly final: boolean;
    /** An array of per-recipient authentication data */
    readonly authenticators: Uint8Array[];
    /** The NaCl secretbox for this payload */
    readonly payload_secretbox: Uint8Array;
    private _encoded_data: Buffer | null = null;

    constructor(final: boolean, authenticators: Uint8Array[], payload_secretbox: Uint8Array) {
        this.final = final;
        this.authenticators = authenticators;
        this.payload_secretbox = payload_secretbox;
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
        header: EncryptedMessageHeader, payload_key: Buffer, data: Buffer, index: bigint, final = false
    ): EncryptedMessagePayload {
        const index_buffer = Buffer.alloc(8);
        index_buffer.writeBigUInt64BE(index);
        const nonce = Buffer.concat([this.PAYLOAD_NONCE_PREFIX, index_buffer]);

        const payload_secretbox = Buffer.from(tweetnacl.secretbox(data, nonce, payload_key));

        const authenticator_hash = this.generateAuthenticatorHash(header.hash, payload_secretbox, nonce, final);

        return new this(final, header.recipients.map((recipient, i) => {
            if (!recipient.mac_key) {
                throw new Error('Recipient #' + i + ' doesn\'t have a MAC key set');
            }

            // 3. For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash
            // from #2, using that recipient's MAC key.
            // return substr(sodium_crypto_auth($authenticator_hash, $recipient->mac_key), 0, 32);
            return crypto.createHmac('sha512', recipient.mac_key).update(authenticator_hash).digest().slice(0, 32);
        }), payload_secretbox);
    }

    static generateAuthenticatorHash(
        header_hash: Buffer, payload_secretbox: Uint8Array, payload_secretbox_nonce: Uint8Array, final: boolean
    ): Buffer {
        // 1. Concatenate the header hash, the nonce for the payload secretbox, the final flag byte (0x00 or 0x01),
        // and the payload secretbox itself.
        // 2. Compute the crypto_hash (SHA512) of the bytes from #1.
        return crypto.createHash('sha512')
            .update(header_hash)
            .update(payload_secretbox_nonce)
            .update(final ? '\x01' : '\x00')
            .update(payload_secretbox)
            .digest();
    }

    encode() {
        return EncryptedMessagePayload.encodePayload(this.final, this.authenticators, this.payload_secretbox);
    }

    /**
     * @param int $mode
     * @param string $public_key
     * @param string $sender
     * @param string[] $authenticators
     * @return [string, string]
     */
    static encodePayload(final: boolean, authenticators: Uint8Array[], payload_secretbox: Uint8Array): Buffer {
        const data = [
            final,
            authenticators,
            payload_secretbox,
        ];

        return Buffer.from(msgpack.encode(data));
    }

    static decode(encoded: any, unpacked = false): EncryptedMessagePayload {
        const data = unpacked ? encoded : msgpack.decode(encoded) as any;

        if (data.length < 3) throw new Error('Invalid data');

        const [final, authenticators, payload_secretbox] = data;

        return new this(final, authenticators, payload_secretbox);
    }

    decrypt(header: EncryptedMessageHeader, recipient: EncryptedMessageRecipient, payload_key: Buffer, index: bigint) {
        if (!recipient.mac_key) {
            throw new Error('Recipient doesn\'t have a MAC key set');
        }

        // @ts-expect-error
        const authenticator: Uint8Array | undefined = this.authenticators[recipient.index];

        const index_buffer = Buffer.alloc(8);
        index_buffer.writeBigUInt64BE(index);
        const nonce = Buffer.concat([EncryptedMessagePayload.PAYLOAD_NONCE_PREFIX, index_buffer]);

        const authenticator_hash = EncryptedMessagePayload.generateAuthenticatorHash(
            header.hash, this.payload_secretbox, nonce, this.final
        );

        // 3. For each recipient, compute the crypto_auth (HMAC-SHA512, truncated to 32 bytes) of the hash
        // from #2, using that recipient's MAC key.
        // const our_authenticator = substr(sodium_crypto_auth($authenticator_hash, $recipient->mac_key), 0, 32);
        const our_authenticator = crypto.createHmac('sha512', recipient.mac_key)
            .update(authenticator_hash).digest().slice(0, 32);

        if (!authenticator || !our_authenticator.equals(authenticator)) {
            throw new Error('Invalid authenticator');
        }

        const decrypted = tweetnacl.secretbox.open(this.payload_secretbox, nonce, payload_key);

        if (!decrypted) {
            throw new Error('Failed to decrypt data');
        }

        return decrypted;
    }
}
