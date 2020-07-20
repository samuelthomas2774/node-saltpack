import {
    armor, dearmor,
    ArmorStream,
    DearmorStream,
    encodeBlock, decodeBlock,
    Options,
    efficientCharsSizes,
} from '../armor';

const INPUT_STRING = 'Two roads diverged in a yellow wood, and sorry I could not travel both\n' +
    'and be one traveller, long I stood, and looked down one as far as I\n' +
    'could, to where it bent in the undergrowth.';

test('round trip', () => {
    const encoded = armor(INPUT_STRING);
    const decoded = dearmor(encoded);

    expect(decoded.toString()).toBe(INPUT_STRING);
    expect(decoded.header_info!.message_type).toBe('MESSAGE');
    expect(decoded.header_info!.app_name).toBe(null);
});

test('round trip in raw format', () => {
    const options: Partial<Options> = {raw: true};

    const encoded = armor(INPUT_STRING, options);
    const decoded = dearmor(encoded, options);

    expect(decoded.toString()).toBe(INPUT_STRING);
    expect(decoded.header_info).toBe(null);
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

    expect(result.join('')).toEqual(expected);
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

    expect(result.join('')).toEqual(INPUT_STRING);
    expect(stream.info!.message_type).toEqual('MESSAGE');
    expect(stream.info!.app_name).toEqual(null);
});
