import * as tweetnacl from 'tweetnacl';

export const KEYPAIR = tweetnacl.box.keyPair.fromSecretKey(Buffer.from(
    '5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f196', 'hex'));
export const KEYPAIR_ALICE = tweetnacl.box.keyPair.fromSecretKey(Buffer.from(
    '5ce86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef3ee', 'hex'));
export const KEYPAIR_BOB = tweetnacl.box.keyPair.fromSecretKey(Buffer.from(
    'aa3c626bc9c38c8c201878ebb1d5b0b50ac40e8986c78793db1d4ef369fca1ce', 'hex'));
export const KEYPAIR_MALLORY = tweetnacl.box.keyPair.fromSecretKey(Buffer.from(
    '98aebbb178a551876bfaf8e1e530dac6aaf6c2ea1c8f8406a3ab37dfb40fbc25', 'hex'));
