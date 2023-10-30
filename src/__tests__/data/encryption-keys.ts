import tweetnacl from 'tweetnacl';

export const KEYPAIR = tweetnacl.box.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f196', 'hex')));
export const KEYPAIR_ALICE = tweetnacl.box.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '5ce86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef3ee', 'hex')));
export const KEYPAIR_BOB = tweetnacl.box.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    'aa3c626bc9c38c8c201878ebb1d5b0b50ac40e8986c78793db1d4ef369fca1ce', 'hex')));
export const KEYPAIR_MALLORY = tweetnacl.box.keyPair.fromSecretKey(Uint8Array.from(Buffer.from(
    '98aebbb178a551876bfaf8e1e530dac6aaf6c2ea1c8f8406a3ab37dfb40fbc25', 'hex')));

export const SYMMETRIC_KEY_BOB = Buffer.from(
    'c5db2c6f47009e06f0a4e9e479f62c300436165ac98956b1a42e5c44e3a1ada7', 'hex');
export const SYMMETRIC_KEY_MALLORY = Buffer.from(
    'c6f6e3cdeda10449bb91841a141517baf0cd8c06e15843dcf201284ce41063f1', 'hex');
