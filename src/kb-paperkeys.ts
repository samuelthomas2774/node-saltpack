import * as crypto from 'node:crypto';
import tweetnacl, { BoxKeyPair, SignKeyPair } from 'tweetnacl';

// https://github.com/keybase/client/blob/38a96307aa34f4ebafff79aa45a7c6245dd2ae38/go/libkb/constants.go#L564-L578
const SCRYPT_COST = 32768; // 2 ** 15
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 128;

export class PaperKey {
    private readonly data!: Uint8Array;

    constructor(
        data: Uint8Array,
        readonly label?: string,
    ) {
        Object.defineProperty(this, 'data', {
            configurable: false,
            value: data instanceof Buffer ? new Uint8Array(data) : data,
        });
    }

    static async from(paper_key: string) {
        const key = await new Promise<Buffer>((rs, rj) => crypto.scrypt(Buffer.from(paper_key), Buffer.alloc(0), SCRYPT_KEYLEN, {
            cost: SCRYPT_COST,
            blockSize: SCRYPT_R,
            parallelization: SCRYPT_P,
            maxmem: SCRYPT_COST * SCRYPT_R * 1024,
        }, (err, key) => err ? rj(err) : rs(key)));

        return new PaperKey(key, paper_key.match(/^([a-z]+ [a-z]+) /)?.[1]);
    }

    get eddsa_seed(): Uint8Array {
        return Object.defineProperty(this, 'eddsa_seed', {
            configurable: false,
            value: this.data.slice(32, 64),
        }).eddsa_seed;
    }

    get dh_seed(): Uint8Array {
        return Object.defineProperty(this, 'dh_seed', {
            configurable: false,
            value: this.data.slice(64, 96),
        }).dh_seed;
    }

    get signing_keypair(): SignKeyPair {
        return Object.defineProperty(this, 'signing_keypair', {
            configurable: false,
            value: tweetnacl.sign.keyPair.fromSeed(this.eddsa_seed),
        }).signing_keypair;
    }

    get encryption_keypair(): BoxKeyPair {
        return Object.defineProperty(this, 'encryption_keypair', {
            configurable: false,
            value: tweetnacl.box.keyPair.fromSecretKey(this.dh_seed),
        }).encryption_keypair;
    }
}
