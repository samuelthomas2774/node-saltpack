
import Header, { MessageType } from '../message-header.js';
import SigncryptedMessageRecipient from './recipient.js';
import * as crypto from 'crypto';
import tweetnacl from 'tweetnacl';
import * as msgpack from '@msgpack/msgpack';
import { isBufferOrUint8Array } from '../util.js';

export default class SigncryptedMessageHeader extends Header {
    static readonly SENDER_KEY_SECRETBOX_NONCE = Buffer.from('saltpack_sender_key_sbox');

    /** The 32 byte X25519 ephemeral public key */
    readonly public_key: Uint8Array;
    /**
     * A NaCl secretbox containing the sender's actual X25519 public key (or the epemeral public key, if the
     * sender wishes to be anonymous)
     */
    readonly sender_secretbox: Uint8Array;
    /** An array of recipient objects */
    readonly recipients: SigncryptedMessageRecipient[];

    constructor(public_key: Uint8Array, sender_secretbox: Uint8Array, recipients: SigncryptedMessageRecipient[]) {
        super();

        if (!isBufferOrUint8Array(public_key) || public_key.length !== 32) {
            throw new TypeError('public_key must be a 32 byte Uint8Array');
        }
        if (!isBufferOrUint8Array(sender_secretbox) || sender_secretbox.length !== 48) {
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
        public_key: Uint8Array, payload_key: Uint8Array, sender_public_key: Uint8Array | null,
        recipients: SigncryptedMessageRecipient[]
    ) {
        if (sender_public_key !== null &&
            (!isBufferOrUint8Array(sender_public_key) || sender_public_key.length !== 32)
        ) {
            throw new TypeError('sender_public_key must be a 32 byte Uint8Array');
        }
        if (!isBufferOrUint8Array(payload_key) || payload_key.length !== 32) {
            throw new TypeError('payload_key must be a 32 byte Uint8Array');
        }

        // If Alice wants to be anonymous to recipients as well, she can supply an all-zero signing public key in
        // step #3.
        if (!sender_public_key) sender_public_key = Buffer.alloc(32);

        // 3. Encrypt the sender's long-term public key signing key using crypto_secretbox with the payload key and
        // the nonce saltpack_sender_key_sbox, to create the sender secretbox.
        const sender_secretbox = tweetnacl.secretbox(
            Uint8Array.from(sender_public_key),
            Uint8Array.from(SigncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE),
            Uint8Array.from(payload_key),
        );

        return new this(public_key, sender_secretbox, recipients);
    }

    encode() {
        return SigncryptedMessageHeader.encodeHeader(this.public_key, this.sender_secretbox, this.recipients);
    }

    static encodeHeader(
        public_key: Uint8Array, sender: Uint8Array, recipients: SigncryptedMessageRecipient[]
    ): [Buffer, Buffer] {
        const data = [
            'saltpack',
            [2, 0],
            MessageType.SIGNCRYPTION,
            public_key,
            sender,
            recipients.map(recipient => {
                // [
                //     recipient identifier,
                //     payload key box,
                // ]

                return [
                    recipient.recipient_identifier,
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

        if (data[2] !== MessageType.SIGNCRYPTION) throw new Error('Invalid data');
        const [,,, public_key, sender_secretbox, recipients] = data;

        if (!(recipients instanceof Array)) throw new Error('Invalid data');

        return new this(public_key as any, sender_secretbox as any, recipients.map((recipient: unknown, index) => {
            if (!(recipient instanceof Array) || recipient.length < 2) {
                throw new TypeError('Invalid data');
            }

            return SigncryptedMessageRecipient.from(recipient[0], recipient[1], index);
        }));
    }

    /**
     * Decrypts and returns the payload key and recipient.
     */
    decryptPayloadKeyWithCurve25519Keypair(private_key: Uint8Array): [Uint8Array, SigncryptedMessageRecipient] | null {
        // 5. Check to see if any of the recipient's Curve25519 private keys are in the recipients' list. For each
        // private key available, and for each recipient entry in the list, compute the identifier as in step #4
        // in the previous section. If any of the recipient entries match, decrypt the payload key and proceed to
        // step #7.

        for (const recipient of this.recipients) {
            const {recipient_identifier, shared_symmetric_key} =
                SigncryptedMessageRecipient.generateRecipientIdentifierForRecipient(
                    this.public_key, private_key, recipient.recipient_index
                );

            if (!recipient_identifier.equals(recipient.recipient_identifier)) continue;

            const payload_key = recipient.decryptPayloadKey(shared_symmetric_key);

            if (!payload_key) {
                throw new Error('Invalid shared symmetric key');
            }

            return [payload_key, recipient];
        }

        return null;
    }

    decryptPayloadKeyWithSymmetricKey(
        shared_symmetric_key: Uint8Array, recipient_identifier?: Uint8Array | null
    ): [Uint8Array, SigncryptedMessageRecipient] | null {
        // 6. If no Curve25519 keys matched in the previous step, check whether any of the recipient's symmetric
        // keys are in the message. The identifiers in this step are up to the application, and if the space of
        // possible keys is very large, the recipient might use server assistance to look up identifiers. If any
        // of the recipient entries match, decrypt the payload key. If not, decryption fails, and the client should
        // report that the current user isn't a recipient of this message.

        const derived_key = crypto
            .createHmac('sha512', SigncryptedMessageRecipient.HMAC_KEY_SYMMETRIC)
            .update(this.public_key)
            .update(shared_symmetric_key)
            .digest()
            .slice(0, 32);

        const identifier = recipient_identifier ? Buffer.from(recipient_identifier) : null;

        for (const recipient of this.recipients) {
            if (identifier && !identifier.equals(recipient.recipient_identifier)) continue;

            const payload_key = recipient.decryptPayloadKey(derived_key);

            if (!payload_key) continue;

            return [payload_key, recipient];
        }

        return null;
    }

    decryptSender(payload_key: Uint8Array): Uint8Array | null {
        const sender_public_key = tweetnacl.secretbox.open(
            Uint8Array.from(this.sender_secretbox),
            Uint8Array.from(SigncryptedMessageHeader.SENDER_KEY_SECRETBOX_NONCE),
            Uint8Array.from(payload_key),
        );

        if (!sender_public_key) {
            throw new Error('Failed to decrypt sender public key');
        }

        if (Buffer.alloc(32).equals(sender_public_key)) {
            return null;
        }

        return sender_public_key;
    }
}
