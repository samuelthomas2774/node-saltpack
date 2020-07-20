
// @ts-ignore
global.Uint8Array = Buffer.__proto__;

import {armor, MessageType} from '../armor';
import {
    encryptAndArmor, dearmorAndDecrypt,
    EncryptAndArmorStream, DearmorAndDecryptStream,
    signAndArmor, verifyArmored,
    SignAndArmorStream, DearmorAndVerifyStream,
} from '../with-armor';
import * as Encryption from '../encryption';
import SignedMessageHeader from '../signing/header';

import {INPUT_STRING} from './data/common';
import {KEYPAIR as ENCRYPTION_KEYPAIR, KEYPAIR_ALICE, KEYPAIR_BOB, KEYPAIR_MALLORY} from './data/encryption-keys';
import {ENCRYPTED} from './data/encryption-tests';
import {KEYPAIR as SIGNING_KEYPAIR} from './data/signing-keys';
import {SIGNED} from './data/signing-tests';

// @ts-ignore
Encryption.debug_fix_key = Buffer.alloc(32).fill('\x00');
// @ts-ignore
Encryption.debug_fix_keypair = ENCRYPTION_KEYPAIR;

SignedMessageHeader.debug_fix_nonce = Buffer.alloc(32).fill('\x00');

test('encryption and armoring', async () => {
    const expected = armor(ENCRYPTED, {message_type: MessageType.ENCRYPTED_MESSAGE});

    const encrypted = await encryptAndArmor(INPUT_STRING, KEYPAIR_ALICE, [
        KEYPAIR_BOB.publicKey,
    ]);

    expect(encrypted).toBe(expected);
});

test('streaming encryption and armoring', async () => {
    const expected = armor(ENCRYPTED, {message_type: MessageType.ENCRYPTED_MESSAGE});
    const result: string[] = [];

    const stream = new EncryptAndArmorStream(KEYPAIR_ALICE, [
        KEYPAIR_BOB.publicKey,
    ]);

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk.toString()));

        stream.end(INPUT_STRING);
    });

    expect(result.join('')).toBe(expected);
});

test('dearmoring and decryption', async () => {
    const encrypted = armor(ENCRYPTED, {message_type: MessageType.ENCRYPTED_MESSAGE});

    const decrypted = await dearmorAndDecrypt(encrypted, KEYPAIR_BOB);

    expect(decrypted.toString()).toBe(INPUT_STRING);
    expect(decrypted.sender_public_key).toStrictEqual(Buffer.from(KEYPAIR_ALICE.publicKey));
});

test('streaming dearmoring and decryption', async () => {
    const armored = armor(ENCRYPTED, {message_type: MessageType.ENCRYPTED_MESSAGE});
    const result: string[] = [];

    const stream = new DearmorAndDecryptStream(KEYPAIR_BOB);

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(armored);
    });

    expect(result.join('')).toBe(INPUT_STRING);
    expect(stream.info.message_type).toBe(MessageType.ENCRYPTED_MESSAGE);
    expect(stream.info.app_name).toBe(null);
    expect(stream.sender_public_key).toStrictEqual(Buffer.from(KEYPAIR_ALICE.publicKey));
});

test('dearmor and decrypt with wrong keypair fails', async () => {
    await expect(async () => {
        const encrypted = armor(ENCRYPTED, {message_type: MessageType.ENCRYPTED_MESSAGE});

        await dearmorAndDecrypt(encrypted, KEYPAIR_MALLORY);
    }).rejects.toThrow();
});

test('signing and armoring', async () => {
    const expected = armor(SIGNED, {message_type: MessageType.SIGNED_MESSAGE});

    const signed = await signAndArmor(INPUT_STRING, SIGNING_KEYPAIR);

    expect(signed).toBe(expected);
});

test('streaming signing and armoring', async () => {
    const expected = armor(SIGNED, {message_type: MessageType.SIGNED_MESSAGE});
    const result: string[] = [];

    const stream = new SignAndArmorStream(SIGNING_KEYPAIR);

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk.toString()));

        stream.end(INPUT_STRING);
    });

    expect(result.join('')).toBe(expected);
});

test('dearmoring and verifying', async () => {
    const signed = armor(SIGNED, {message_type: MessageType.SIGNED_MESSAGE});

    const verified = await verifyArmored(signed, SIGNING_KEYPAIR.publicKey);

    expect(verified.toString()).toStrictEqual(INPUT_STRING);
    // expect(verified.info.message_type).toBe('DETACHED SIGNATURE');
    // expect(verified.info.app_name).toBe(null);
});

test('streaming dearmoring and verifying', async () => {
    const armored = armor(SIGNED, {message_type: MessageType.SIGNED_MESSAGE});
    const result: string[] = [];

    const stream = new DearmorAndVerifyStream(SIGNING_KEYPAIR.publicKey);

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk.toString()));

        stream.end(armored);
    });

    expect(result.join('')).toBe(INPUT_STRING);
    expect(stream.info.message_type).toBe(MessageType.SIGNED_MESSAGE);
    expect(stream.info.app_name).toBe(null);
});
