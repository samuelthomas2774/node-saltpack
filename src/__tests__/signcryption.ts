
// @ts-ignore
global.Uint8Array = Buffer.__proto__;

import * as Signcryption from '../signcryption';
import {signcrypt, designcrypt, SigncryptStream, DesigncryptStream} from '../signcryption';

// With signcryption the sender *signs the message* with their Ed25519 key, and *encrypts for recipients'*
// Curve25519 keys - so Alice, the sender, uses a signing key and Bob, the recipient, uses an encryption key
import {KEYPAIR, /*KEYPAIR_ALICE,*/ KEYPAIR_BOB, KEYPAIR_MALLORY} from './data/encryption-keys';
import {KEYPAIR_ALICE /*, KEYPAIR_BOB as KEYPAIR_BOB_S */} from './data/signing-keys';
import {INPUT_STRING, SIGNCRYPTED} from './data/signcryption-tests';

// @ts-ignore
Signcryption.debug_fix_key = Buffer.alloc(32).fill('\x00');
// @ts-ignore
Signcryption.debug_fix_keypair = KEYPAIR;

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
    const data = await designcrypt(SIGNCRYPTED, KEYPAIR_BOB);

    expect(data.toString()).toBe(INPUT_STRING);
    expect(data.sender_public_key).toStrictEqual(KEYPAIR_ALICE.publicKey);
});

test('decrypt stream', async () => {
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
