
import Header, {MessageType} from '../message-header';
import EncryptedMessageRecipient from './recipient';
import * as crypto from 'crypto';
import * as tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';

export default class EncryptedMessageHeader extends Header {
    static readonly SENDER_KEY_SECRETBOX_NONCE = Buffer.from('saltpack_sender_key_sbox');

    /** The 32 byte X25519 ephemeral public key */
    readonly public_key: Uint8Array;
    /**
     * A NaCl secretbox containing the sender's actual X25519 public key (or the epemeral public key, if the
     * sender wishes to be anonymous)
     */
    readonly sender_secretbox: Uint8Array;
    /** An array of recipient objects */
    readonly recipients: EncryptedMessageRecipient[];

    constructor(public_key: Uint8Array, sender_secretbox: Uint8Array, recipients: EncryptedMessageRecipient[]) {
        super();

        if (!(public_key instanceof Uint8Array) || public_key.length !== 32) {
            throw new TypeError('public_key must be a 32 byte Uint8Array');
        }
        if (!(sender_secretbox instanceof Uint8Array) || sender_secretbox.length !== 48) {
            throw new TypeError('sender_secretbox must be a 48 byte Uint8Array');
        }

        this.public_key = public_key;
        this.sender_secretbox = sender_secretbox;
        this.recipients = recipients;
    }

    get encoded_data(): [Buffer, Buffer] {
        return Object.defineProperty(this, 'encoded_data', {
            value: this.encode(),
        }).encoded_data;
    }

    /** The MessagePack encoded outer header data */
    get encoded() {
        return this.encoded_data[1];
    }
    /** The SHA512 hash of the MessagePack encoded inner header data */
    get hash() {
        return this.encoded_data[0];
    }

    static create(
        public_key: Uint8Array, payload_key: Uint8Array, sender_public_key: Uint8Array,
        recipients: EncryptedMessageRecipient[]
    ) {
        if (!(sender_public_key instanceof Uint8Array) || sender_public_key.length !== 32) {
            throw new TypeError('sender_public_key must be a 32 byte Uint8Array');
        }
        if (!(payload_key instanceof Uint8Array) || payload_key.length !== 32) {
            throw new TypeError('payload_key must be a 32 byte Uint8Array');
        }

        // 3. Encrypt the sender's long-term public key using crypto_secretbox with the payload key and the nonce saltpack_sender_key_sbox, to create the sender secretbox.
        // const sender_secretbox = sodium_crypto_secretbox($sender_public_key, self::SENDER_KEY_SECRETBOX_NONCE, $payload_key);
        const sender_secretbox = tweetnacl.secretbox(
            sender_public_key, EncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE, payload_key
        );

        return new this(public_key, sender_secretbox, recipients);
    }

    encode() {
        return EncryptedMessageHeader.encodeHeader(this.public_key, this.sender_secretbox, this.recipients);
    }

    static encodeHeader(
        public_key: Uint8Array, sender: Uint8Array, recipients: EncryptedMessageRecipient[]
    ): [Buffer, Buffer] {
        const data = [
            'saltpack',
            [2, 0],
            MessageType.ENCRYPTION,
            public_key,
            sender,
            recipients.map(recipient => {
                // [
                //     recipient public key,
                //     payload key box,
                // ]

                return [
                    recipient.anonymous ? null : recipient.public_key,
                    recipient.encrypted_payload_key,
                ];
            }),
        ];

        const encoded = msgpack.encode(data);

        const header_hash = crypto.createHash('sha512').update(encoded).digest();

        return [header_hash, Buffer.from(msgpack.encode(encoded))];
    }

    static decode(encoded: Uint8Array, unwrapped = false) {
        const [header_hash, data] = super.decode1(encoded, unwrapped);

        if (data[2] !== MessageType.ENCRYPTION) throw new Error('Invalid data');
        const [,,, public_key, sender_secretbox, recipients] = data;

        if (!(recipients instanceof Array)) throw new Error('Invalid data');

        return new this(public_key as any, sender_secretbox as any, recipients.map((recipient: unknown, index) => {
            if (!(recipient instanceof Array) || recipient.length < 2) {
                throw new TypeError('Invalid data');
            }

            return EncryptedMessageRecipient.from(recipient[0], recipient[1], index);
        }));
    }

    /**
     * Decrypts and returns the payload key and recipient.
     */
    decryptPayloadKey(keypair: tweetnacl.BoxKeyPair): [Uint8Array, EncryptedMessageRecipient] {
        // 5. Precompute the ephemeral shared secret using crypto_box_beforenm with the ephemeral public key and
        // the recipient's private key.
        const shared_secret = tweetnacl.box.before(this.public_key, keypair.secretKey);

        // 6. Try to open each of the payload key boxes in the recipients list using crypto_box_open_afternm,
        // the precomputed secret from #5, and the nonce saltpack_recipsbXXXXXXXX. XXXXXXXX is 8-byte big-endian
        // unsigned recipient index, where the first recipient is index 0. Successfully opening one gives the
        // payload key.

        for (const recipient of this.recipients) {
            if (recipient.public_key) {
                // If the recipient's public key is shown in the recipients list (that is, if the recipient is
                // not anonymous), clients may skip all the other payload key boxes in step #6.
                if (!Buffer.from(recipient.public_key).equals(keypair.publicKey)) continue;
            }

            const payload_key = recipient.decryptPayloadKey(this.public_key, keypair.secretKey, shared_secret);
            if (!payload_key) continue;

            recipient.setPublicKey(keypair.publicKey);

            return [payload_key, recipient];
        }

        throw new Error('keypair is not an intended recipient');
    }

    decryptSender(payload_key: Uint8Array): Uint8Array {
        const sender_public_key = tweetnacl.secretbox.open(
            this.sender_secretbox, EncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE, payload_key
        );

        if (!sender_public_key) {
            throw new Error('Failed to decrypt sender public key');
        }

        return sender_public_key;
    }
}
