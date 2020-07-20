export {
    armor,
    ArmorStream,

    dearmor,
    DearmorStream,

    DearmorResult,
    ArmorHeaderInfo,
    Options as ArmorOptions,
} from './armor';

export {MessageType} from './message-header';

export {
    encrypt,
    EncryptStream,

    decrypt,
    DecryptStream,

    DecryptResult,
} from './encryption';

export {
    sign,
    SignStream,

    verify,
    VerifyStream,

    signDetached,
    verifyDetached,
} from './signing';

import {MultiTransform} from './util';
import {encrypt, decrypt, EncryptStream, DecryptStream} from './encryption';
import {sign, verify, SignStream, VerifyStream, signDetached, verifyDetached} from './signing';
import {armor, dearmor, ArmorStream, DearmorStream, Options as ArmorOptions, MessageType} from './armor';
import * as tweetnacl from 'tweetnacl';

export async function encryptAndArmor(
    data: Uint8Array | string, keypair: tweetnacl.BoxKeyPair | null, recipients_keys: Uint8Array[]
) {
    const encrypted = await encrypt(data, keypair, recipients_keys);
    return armor(encrypted, {message_type: MessageType.ENCRYPTED_MESSAGE});
}
export async function dearmorAndDecrypt(encrypted: Uint8Array, keypair: tweetnacl.BoxKeyPair) {
    const dearmored = dearmor(encrypted);
    return await decrypt(dearmored, keypair);
}

export class EncryptAndArmorStream extends MultiTransform {
    static constructors = [EncryptStream, ArmorStream];

    constructor(armor_options?: Partial<ArmorOptions>) {
        super([], [Object.assign({
            message_type: MessageType.ENCRYPTED_MESSAGE,
        }, armor_options)]);
    }
}
export class DearmorAndDecryptStream extends MultiTransform {
    static constructors = [DearmorStream, DecryptStream];

    constructor(armor_options?: Partial<ArmorOptions>) {
        super([armor_options]);
    }

    get sender_public_key(): Buffer {
        // @ts-ignore
        return this.streams[1].sender_public_key;
    }
}

export async function signAndArmor(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair) {
    const signed = sign(data, keypair);
    return armor(signed, {message_type: MessageType.SIGNED_MESSAGE});
}
export async function verifyArmored(signed: Uint8Array, public_key: Uint8Array) {
    const dearmored = dearmor(signed);
    return await verify(dearmored, public_key);
}

export class SignAndArmorStream extends MultiTransform {
    static constructors = [SignStream, ArmorStream];

    constructor(keypair: tweetnacl.SignKeyPair, armor_options?: Partial<ArmorOptions>) {
        super([keypair], [Object.assign({
            message_type: MessageType.SIGNED_MESSAGE,
        }, armor_options)]);
    }
}
export class DearmorAndVerifyStream extends MultiTransform {
    static constructors = [DearmorStream, VerifyStream];

    constructor(public_key: Uint8Array, armor_options?: Partial<ArmorOptions>) {
        super([armor_options], [public_key]);
    }
}

export async function signDetachedAndArmor(data: Uint8Array | string, keypair: tweetnacl.SignKeyPair) {
    const signed = signDetached(data, keypair);
    return armor(signed, {message_type: MessageType.DETACHED_SIGNATURE});
}
export async function verifyDetachedArmored(signed: Uint8Array, data: Uint8Array | string, public_key: Uint8Array) {
    const dearmored = dearmor(signed);
    return await verifyDetached(dearmored, data, public_key);
}
