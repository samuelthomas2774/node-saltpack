
import * as crypto from 'crypto';
import * as msgpack from '@msgpack/msgpack';

export enum MessageType {
    ENCRYPTION = 0,
    ATTACHED_SIGNING = 1,
    DETACHED_SIGNING = 2,
    SIGNCRYPTION = 3,
}

export default class Header {
    static decode1(encoded: Buffer, unwrapped = false) {
        // 1-3
        const data = unwrapped ? encoded : msgpack.decode(encoded) as Buffer;
        const header_hash = crypto.createHash('sha512').update(data).digest();
        const inner = msgpack.decode(data) as any;

        // 4
        if (inner.length < 2) throw new Error('Invalid data');

        const [format_name, version, mode] = inner;

        if (format_name !== 'saltpack') throw new Error('Invalid data');
        if (version.length !== 2) throw new Error('Invalid data');

        if (version[0] !== 2) throw new Error('Unsupported version');
        if (version[1] !== 0) throw new Error('Unsupported version');

        return [header_hash, inner];
    }
}
