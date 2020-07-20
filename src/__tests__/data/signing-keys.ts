import * as tweetnacl from 'tweetnacl';

export const KEYPAIR = tweetnacl.sign.keyPair.fromSecretKey(Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29', 'hex'));
