
// @ts-ignore
global.Uint8Array = Buffer.__proto__;

import {sign, verify, SignStream, VerifyStream, signDetached, verifyDetached} from '../signing';
import SignedMessageHeader from '../signing/header';

import {KEYPAIR} from './data/signing-keys';
import {INPUT_STRING, SIGNED, DETACHED_SIGNATURE} from './data/signing-tests';

SignedMessageHeader.debug_fix_nonce = Buffer.alloc(32).fill('\x00');

describe('attached signing', () => {
    test('sign', () => {
        const signed = sign(INPUT_STRING, KEYPAIR);

        expect(signed).toStrictEqual(SIGNED);
    });

    test('sign stream', async () => {
        const stream = new SignStream(KEYPAIR);
        const result: Buffer[] = [];

        await new Promise((rs, rj) => {
            stream.on('error', rj);
            stream.on('end', rs);
            stream.on('data', chunk => result.push(chunk));

            stream.end(INPUT_STRING);
        });

        expect(Buffer.concat(result)).toStrictEqual(SIGNED);
    });

    test('verify', async () => {
        const data = await verify(SIGNED, KEYPAIR.publicKey);

        expect(data.toString()).toBe(INPUT_STRING);
    });

    test('verify stream', async () => {
        const stream = new VerifyStream(KEYPAIR.publicKey);
        const result: Buffer[] = [];

        await new Promise((rs, rj) => {
            stream.on('error', rj);
            stream.on('end', rs);
            stream.on('data', chunk => result.push(chunk));

            stream.end(SIGNED);
        });

        expect(Buffer.concat(result).toString()).toBe(INPUT_STRING);
    });

    test('verify with wrong public key fails', () => {
        const public_key = new Uint8Array(KEYPAIR.publicKey);
        public_key[0] = 0;

        expect(async () => {
            await verify(SIGNED, public_key);
        }).rejects.toThrow();
    });
});

describe('detached signing', () => {
    test('sign detached', () => {
        const signed = signDetached(INPUT_STRING, KEYPAIR);
        expect(signed).toStrictEqual(DETACHED_SIGNATURE);
    });

    test('verify detached', async () => {
        await verifyDetached(DETACHED_SIGNATURE, INPUT_STRING, KEYPAIR.publicKey);
    });

    test('verify detached with wrong public key fails', () => {
        const public_key = KEYPAIR.publicKey;
        public_key[0] = 0;

        expect(async () => {
            await verifyDetached(DETACHED_SIGNATURE, INPUT_STRING, public_key);
        }).rejects.toThrow();
    });
});
