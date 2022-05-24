
import { encrypt, decrypt, EncryptStream, DecryptStream, debugSetKeypair, debugSetKey } from '../encryption/index.js';

import { KEYPAIR, KEYPAIR_ALICE, KEYPAIR_BOB, KEYPAIR_MALLORY } from './data/encryption-keys.js';
import { INPUT_STRING, ENCRYPTED } from './data/encryption-tests.js';

debugSetKey(Buffer.alloc(32).fill('\x00'));
debugSetKeypair(KEYPAIR);

test('encrypt', async () => {
    const encrypted = await encrypt(INPUT_STRING, KEYPAIR_ALICE, [
        KEYPAIR_BOB.publicKey,
    ]);

    expect(encrypted).toStrictEqual(ENCRYPTED);
});

test('encrypt stream', async () => {
    const stream = new EncryptStream(KEYPAIR_ALICE, [
        KEYPAIR_BOB.publicKey,
    ]);

    const result: Buffer[] = [];

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(INPUT_STRING);
    });

    expect(Buffer.concat(result)).toStrictEqual(ENCRYPTED);
});

test('decrypt', async () => {
    const data = await decrypt(ENCRYPTED, KEYPAIR_BOB, KEYPAIR_ALICE.publicKey);

    expect(data.toString()).toBe(INPUT_STRING);
    expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt doesn\'t require sender public key', async () => {
    const data = await decrypt(ENCRYPTED, KEYPAIR_BOB);

    expect(data.toString()).toBe(INPUT_STRING);
    expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt stream', async () => {
    const stream = new DecryptStream(KEYPAIR_BOB, KEYPAIR_ALICE.publicKey);
    const result: Buffer[] = [];

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(ENCRYPTED);
    });

    expect(result.toString()).toBe(INPUT_STRING);
    expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt stream doesn\'t require sender public key', async () => {
    const stream = new DecryptStream(KEYPAIR_BOB);
    const result: Buffer[] = [];

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(ENCRYPTED);
    });

    expect(result.toString()).toBe(INPUT_STRING);
    expect(stream.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt with wrong keypair fails', async () => {
    await expect(async () => {
        await decrypt(ENCRYPTED, KEYPAIR_MALLORY);
    }).rejects.toThrow();
});
