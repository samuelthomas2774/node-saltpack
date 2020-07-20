import {
    armor, dearmor,
    ArmorStream,
    DearmorStream,
    encodeBlock, decodeBlock,
    Options,
    efficientCharsSizes,
} from '../armor';

import {INPUT_STRING} from './data/common';
import {ENCRYPTED} from './data/encryption-tests';

const ARMORED = 'BEGIN SALTPACK MESSAGE. K1pqnxb2DkrYwTF eoRpTHfQUiQ8Vhv QcqV2Ijl5OgvHQQ KXoeeJBRilQ1udq ' +
    'YjHoEWwyIgddRVZ SEswTz7nRxdPdgd RVjkX80hz6eArwG S2IaonQ5sEZH3Ia 5qxopd0rWOSAd4W 1MLaAPG3aIif4yU ' +
    'ymurJJlPkXjIGfc L3GAOA5RIbPD2mW YBGP8Ky5cPTzjIv ZERus8MRXpGXzas nYYCr4KgnLRUZEp 3juuuL5RLE5A4qX ' +
    '6jbmY. END SALTPACK MESSAGE.';

const BLOCK = '2ytpAzEXyKTYKdqtKuPHhGNeLdnK5QUeASwFqeXVWkPZUADyvXCVJfrkMjWEztpm' +
    'SyeH2zB3i6pZhR00wiGVBAvnVRRqrqjLhhRJkRKc3qS9uVeVKxOiYtV3LIx0sD4L' +
    'uuwO6Qocfg57zXTelzCbdFgwBQZCqdTxAG0Oc9RygG8SI9YKvlTeAzPaSj76T2vG' +
    'B0Gyl6ELQQIbcBmMBriz2cwFTfY31Y8lzI6EhKIYWYik0WUa823uY';

const ENCRYPTED_ARMORED = 'BEGIN SALTPACK MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ ' +
    'rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P 34lAW3U7RD7FIch XNTBGUhFUP7zlJO 72a09uarIhN4God ' +
    'BYvOpzyUOcjDNz2 a8Tu9CgP2XrrVb5 sGTJN7TBDBBrSwc Q6L50iicGl3ayIM Y02zOx5wnJk4oOC fbt3xOFEKC2HCM0 ' +
    'hDNu9HFeexApAaz mY6uuYwjeCx2moo YroRpeao26spsF9 iSD6UmL7gPjA3YU lFZvtJYx6t3eKlN sl1SmPnLCnhyV9L ' +
    '10hYj7F8YELWJKA BKpZBWnw48xQGWL pun4FEAQONeTnpO 0idRsM41lLrgDeS aHRkSXH702Wjc97 bLKV43Et1MFYwFm ' +
    'P6nFMM0hj0hupfj umu3at5TV1gubnJ snULAcpBmzBTVxK DkjxM3n3mWZdDlK UB9TCTeV556HgaO 15nEqRYJGO2b5RL ' +
    'gu9931xVkZ0wT20 kCLWHR3NxfRTp6R 9rKEP8b2F178xSC lwenoSpkzd5mA2r 2JRr4n65rNdbiw. END SALTPACK MESSAGE.';
const ENCRYPTED_BLOCK = '36lQllTIba4NtvPlWu5xM6jpvab7TBfZRFBNv5FxldjX9bV69ziu7zYLVqBmRKXg' +
    'KN5xi5kRCOgY5iwCRJtUPGidCzZIb94gvwEV9RXMHHc1JGcwyqMYkJRcnKglUfex' +
    'L9VC4LhMmeRunKcpCkXXoLwcKMy4OvWSZ15xGkrZ8TNLMCBph31OsiFwB9Na5kwB' +
    '8uaH0p2Dd4h6EgoJZX5syw7d3n3qghBWfgna2AUeILBxMXj35KrDV1DOd5WwfXeH' +
    '1gCGP9fb2eFySjp0hr0bOlk6ya6F4GItnH3NPmV01PioOCn0C6a3AYARrQnKgjY3' +
    '9oJzaC9dCS1TeRlFOs95W4MAbmDkOeiOy72BeCdrKVfmXEJMfuRAkRO2fha9hoWA' +
    '4AhkRyKwdkWkJWsRsYrGz3NXfxdii7Ym8kooOuMN3qnlMz5Nq5eIpzitNuHIIIj6' +
    'cnJdyhGkrdUJM6mpJU8KugT2Kyn738zhWLc1wVZ3RFCNOItOxmRsFbL4LlOHkmYx' +
    'azgAmok5ZXHhojGVt3XsND42ZPTYgAaXOQBHB6BcqG3E8thWrqmms0RhO';

test('armor', () => {
    const encoded = armor(INPUT_STRING);

    expect(encoded).toBe(ARMORED);
});

test('dearmor', () => {
    const decoded = dearmor(ARMORED);

    expect(decoded.toString()).toBe(INPUT_STRING);
});

test('round trip', () => {
    const encoded = armor(INPUT_STRING);
    const decoded = dearmor(encoded);

    expect(decoded.toString()).toBe(INPUT_STRING);
    expect(decoded.header_info.message_type).toBe('MESSAGE');
    expect(decoded.header_info.app_name).toBe(null);
});

test('round trip in raw format', () => {
    const options: Partial<Options> = {raw: true};

    const encoded = armor(INPUT_STRING, options);
    const decoded = dearmor(encoded, options);

    expect(decoded.toString()).toBe(INPUT_STRING);
    expect(decoded.header_info).toBe(null);
});

test('binary round trip', () => {
    const encoded = armor(ENCRYPTED);
    const decoded = dearmor(encoded);

    expect(decoded.toString()).toBe(ENCRYPTED.toString());
    expect(decoded.header_info.message_type).toBe('MESSAGE');
    expect(decoded.header_info.app_name).toBe(null);
});

test('binary string round trip', () => {
    const encoded = armor(ENCRYPTED.toString());
    const decoded = dearmor(encoded);

    expect(decoded.toString()).toBe(ENCRYPTED.toString());
    expect(decoded.header_info.message_type).toBe('MESSAGE');
    expect(decoded.header_info.app_name).toBe(null);
});

test('armor binary', () => {
    const encoded = armor(ENCRYPTED);

    expect(encoded).toBe(ENCRYPTED_ARMORED);
});

test('dearmor binary', () => {
    const decoded = dearmor(ENCRYPTED_ARMORED);

    expect(decoded.toString()).toBe(ENCRYPTED.toString());
});

test('encode block', () => {
    const encoded = encodeBlock(Buffer.from(INPUT_STRING));

    expect(encoded).toBe(BLOCK);
});

test('decode block', () => {
    const decoded = decodeBlock(BLOCK);

    expect(decoded.toString()).toBe(INPUT_STRING);
});

test('encode binary block', () => {
    const encoded = encodeBlock(ENCRYPTED);

    expect(encoded).toBe(ENCRYPTED_BLOCK);
});

test('decode binary block', () => {
    const decoded = decodeBlock(ENCRYPTED_BLOCK);

    expect(decoded).toStrictEqual(ENCRYPTED);
});

test('block round trip', () => {
    const INPUT_BLOCK = INPUT_STRING.substr(170);

    const encoded = encodeBlock(Buffer.from(INPUT_BLOCK));
    const decoded = decodeBlock(encoded);

    expect(decoded.toString()).toBe(INPUT_BLOCK);
});

test('efficient chars sizes can be calculated for a given alphabet size', () => {
    const results = efficientCharsSizes(64);

    expect(results).toMatchObject([[2, 1, 0.5], [3, 2, 0.6666666666666666], [4, 3, 0.75]]);
});

test('streaming armoring', async () => {
    const expected = armor(INPUT_STRING);
    const result: string[] = [];

    const stream = new ArmorStream();

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(INPUT_STRING);
    });

    expect(result.join('')).toBe(expected);
});

test('streaming binary armoring', async () => {
    const expected = armor(ENCRYPTED);
    const result: string[] = [];

    const stream = new ArmorStream();

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(ENCRYPTED);
    });

    expect(result.join('')).toBe(expected);
});

test('streaming dearmoring', async () => {
    const armored = armor(INPUT_STRING);
    const result: string[] = [];

    const stream = new DearmorStream();

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(armored);
    });

    expect(result.join('')).toBe(INPUT_STRING);
    expect(stream.info!.message_type).toBe('MESSAGE');
    expect(stream.info!.app_name).toBe(null);
});

test('streaming binary dearmoring', async () => {
    const armored = armor(ENCRYPTED);
    const result: Buffer[] = [];

    const stream = new DearmorStream();

    await new Promise((rs, rj) => {
        stream.on('error', rj);
        stream.on('end', rs);
        stream.on('data', chunk => result.push(chunk));

        stream.end(armored);
    });

    expect(Buffer.concat(result)).toStrictEqual(ENCRYPTED);
    expect(stream.info!.message_type).toBe('MESSAGE');
    expect(stream.info!.app_name).toBe(null);
});
