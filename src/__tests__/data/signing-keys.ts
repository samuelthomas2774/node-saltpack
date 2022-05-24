import tweetnacl from 'tweetnacl';

export const KEYPAIR = tweetnacl.sign.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29', 'hex')));
export const KEYPAIR_ALICE = tweetnacl.sign.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '0101010101010101010101010101010101010101010101010101010101010101' +
    '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c', 'hex')));
export const KEYPAIR_BOB = tweetnacl.sign.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '0202020202020202020202020202020202020202020202020202020202020202' +
    '8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394', 'hex')));
export const KEYPAIR_MALLORY = tweetnacl.sign.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '0303030303030303030303030303030303030303030303030303030303030303' +
    'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1', 'hex')));
