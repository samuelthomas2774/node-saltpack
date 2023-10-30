
import { signcrypt, designcrypt, SigncryptStream, DesigncryptStream, debugSetKey, debugSetKeypair } from '../signcryption/index.js';
import { SymmetricKeyRecipient } from '../signcryption/recipient.js';

// With signcryption the sender *signs the message* with their Ed25519 key, and *encrypts for recipients'*
// Curve25519 keys - so Alice, the sender, uses a signing key and Bob, the recipient, uses an encryption key
import { KEYPAIR, /*KEYPAIR_ALICE,*/ KEYPAIR_BOB, KEYPAIR_MALLORY, SYMMETRIC_KEY_BOB, SYMMETRIC_KEY_MALLORY } from './data/encryption-keys.js';
import { KEYPAIR_ALICE /*, KEYPAIR_BOB as KEYPAIR_BOB_S */ } from './data/signing-keys.js';
import { INPUT_STRING, SIGNCRYPTED, SIGNCRYPTED_SYMMETRIC } from './data/signcryption-tests.js';

debugSetKey(Buffer.alloc(32).fill('\x00'));
debugSetKeypair(KEYPAIR);

test('encrypt', async () => {
    const encrypted = await signcrypt(INPUT_STRING, KEYPAIR_ALICE, [
        KEYPAIR_BOB.publicKey,
    ]);

    expect(encrypted).toStrictEqual(SIGNCRYPTED);
});

test('encrypt stream', async () => {
    const stream = new SigncryptStream(KEYPAIR_ALICE, [
        KEYPAIR_BOB.publicKey,
    ]);

    const result: Buffer[] = [];

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(INPUT_STRING);
    });

    expect(Buffer.concat(result)).toStrictEqual(SIGNCRYPTED);
});

test('decrypt', async () => {
    const data = await designcrypt(SIGNCRYPTED, KEYPAIR_BOB, KEYPAIR_ALICE.publicKey);

    expect(data.toString()).toBe(INPUT_STRING);
    expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt doesn\'t require sender public key', async () => {
    const data = await designcrypt(SIGNCRYPTED, KEYPAIR_BOB);

    expect(data.toString()).toBe(INPUT_STRING);
    expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt stream', async () => {
    const stream = new DesigncryptStream(KEYPAIR_BOB, KEYPAIR_ALICE.publicKey);
    const result: Buffer[] = [];

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(SIGNCRYPTED);
    });

    expect(result.toString()).toBe(INPUT_STRING);
    expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt stream doesn\'t require sender public key', async () => {
    const stream = new DesigncryptStream(KEYPAIR_BOB);
    const result: Buffer[] = [];

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(SIGNCRYPTED);
    });

    expect(result.toString()).toBe(INPUT_STRING);
    expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt with wrong keypair fails', async () => {
    await expect(async () => {
        await designcrypt(SIGNCRYPTED, KEYPAIR_MALLORY);
    }).rejects.toThrow();
});

describe('symmetric key recipients', () => {
    test('encrypt for symmetric key', async () => {
        const encrypted = await signcrypt(INPUT_STRING, KEYPAIR_ALICE, [
            new SymmetricKeyRecipient(Buffer.alloc(32), SYMMETRIC_KEY_BOB),
        ]);

        expect(encrypted).toStrictEqual(SIGNCRYPTED_SYMMETRIC);
    });

    test('decrypt with symmetric key', async () => {
        const data = await designcrypt(SIGNCRYPTED_SYMMETRIC,
            new SymmetricKeyRecipient(Buffer.alloc(32), SYMMETRIC_KEY_BOB),
            KEYPAIR_ALICE.publicKey);
    
        expect(data.toString()).toBe(INPUT_STRING);
        expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
    });

    test('encrypt stream with symmetric key', async () => {
        const stream = new SigncryptStream(KEYPAIR_ALICE, [
            new SymmetricKeyRecipient(Buffer.alloc(32), SYMMETRIC_KEY_BOB),
        ]);

        const result: Buffer[] = [];

        await new Promise((rs, rj) => {
            stream.on('error', rj);
            stream.on('end', rs);
            stream.on('data', chunk => result.push(chunk));

            stream.end(INPUT_STRING);
        });

        expect(Buffer.concat(result)).toStrictEqual(SIGNCRYPTED_SYMMETRIC);
    });

    test('decrypt stream with symmetric key', async () => {
        const stream = new DesigncryptStream(
            new SymmetricKeyRecipient(Buffer.alloc(32), SYMMETRIC_KEY_BOB),
            KEYPAIR_ALICE.publicKey);

        const result: Buffer[] = [];

        await new Promise((rs, rj) => {
            stream.on('error', rj);
            stream.on('end', rs);
            stream.on('data', chunk => result.push(chunk));

            stream.end(SIGNCRYPTED_SYMMETRIC);
        });

        expect(result.toString()).toBe(INPUT_STRING);
        expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
    });

    test('decrypt with wrong key fails', async () => {
        await expect(async () => {
            await designcrypt(SIGNCRYPTED,
                new SymmetricKeyRecipient(Buffer.alloc(32), SYMMETRIC_KEY_MALLORY));
        }).rejects.toThrow();
    });
});
