
import * as crypto from 'crypto';
import * as msgpack from '@msgpack/msgpack';

export enum MessageType {
    ENCRYPTION = 0,
    ATTACHED_SIGNING = 1,
    DETACHED_SIGNING = 2,
    SIGNCRYPTION = 3,
}

export default class Header {
    static decode1(encoded: Uint8Array, unwrapped = false): [Buffer, unknown[]] {
        // 1-3
        const data = unwrapped ? encoded : msgpack.decode(encoded) as Uint8Array;
        const header_hash = crypto.createHash('sha512').update(data).digest();
        const inner = msgpack.decode(data);

        // 4
        if (!(inner instanceof Array) || inner.length < 3) {
            throw new Error('Invalid data');
        }

        const [format_name, version, mode] = inner as unknown[];

        if (format_name !== 'saltpack') throw new Error('Invalid data');
        if (!(version instanceof Array) || version.length !== 2) {
            throw new Error('Invalid data');
        }

        if (version[0] !== 2) throw new Error('Unsupported version');
        if (version[1] !== 0) throw new Error('Unsupported version');

        if (typeof mode !== 'number') throw new Error('Invalid data');

        return [header_hash, inner];
    }
}
