
import {MessageType as Mode} from './message-header';
import {Transform, TransformCallback} from 'stream';
import chunk = require('lodash.chunk');

export let debug = false;

/** The Base62 alphabet */
const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** The Base64 alphabet */
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** The Base85 alphabet */
const BASE85_ALPHABET = '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu';

export type Alphabet = typeof BASE62_ALPHABET | typeof BASE64_ALPHABET | typeof BASE85_ALPHABET;

// Also accept message type "MESSAGE"
// (should really be "ENCRYPTED MESSAGE", "SIGNED MESSAGE" or "DETACHED SIGNATURE")
const HEADER_REGEX = /^[>\n\r\t ]*BEGIN[>\n\r\t ]+(([a-zA-Z0-9]+)[>\n\r\t ]+)?SALTPACK[>\n\r\t ]+(MESSAGE|ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$/;
const FOOTER_REGEX = /^[>\n\r\t ]*END[>\n\r\t ]+(([a-zA-Z0-9]+)[>\n\r\t ]+)?SALTPACK[>\n\r\t ]+(MESSAGE|ENCRYPTED[>\n\r\t ]+MESSAGE|SIGNED[>\n\r\t ]+MESSAGE|DETACHED[>\n\r\t ]+SIGNATURE)[>\n\r\t ]*$/;

export enum MessageType {
    ENCRYPTED_MESSAGE = 'ENCRYPTED MESSAGE',
    SIGNED_MESSAGE = 'SIGNED MESSAGE',
    DETACHED_SIGNATURE = 'DETACHED SIGNATURE',

    /** @private */
    // MESSAGE = 'MESSAGE',
}

function modeToStringType(type: Mode): MessageType {
    switch (type) {
        case Mode.ENCRYPTION: return MessageType.ENCRYPTED_MESSAGE;
        case Mode.ATTACHED_SIGNING: return MessageType.SIGNED_MESSAGE;
        case Mode.DETACHED_SIGNING: return MessageType.DETACHED_SIGNATURE;
        case Mode.SIGNCRYPTION: return MessageType.ENCRYPTED_MESSAGE;
        default: return 'MESSAGE' as MessageType;
    }
}

export interface Options {
    /** The BaseX alphabet - usually Base62, or less frequently Base64 or Base85 */
    alphabet: Alphabet;
    block_size: number;
    char_block_size: number;
    /** Whether to output raw ASCII-armored data or include the header+footer */
    raw: boolean;
    shift: boolean;
    /** The message type to use in the header+footer */
    message_type: MessageType | Mode;
    /** The application name to use in the header+footer */
    app_name: string | null; // Application name (e.g. "KEYBASE")
}

/** The default options used by the armor/dearmor methods. */
const DEFAULT_OPTIONS: Options = {
    alphabet: BASE62_ALPHABET,
    block_size: 32,
    char_block_size: 43,
    raw: false,
    shift: false,
    message_type: 'MESSAGE' as MessageType,
    app_name: null, // Application name (e.g. "KEYBASE")
};

/** Return the index of the specified +char+ in +alphabet+, raising an appropriate error if it is not found. */
function getCharIndex(alphabet: string, char: string) {
    const rval = alphabet.indexOf(char);
    if (rval === -1) {
        throw new Error('Could not find ' + char + ' in alphabet ' + alphabet);
    }
    return rval;
}

/** Return the minimum number of characters needed to encode +bytes_size+ bytes using the given +alphabet+. */
function characterBlockSize(alphabet_size: number, bytes_size: number) {
    return Math.ceil(8 * bytes_size / Math.log2(alphabet_size));
}

/** Return the maximum number of bytes needed to encode +chars_size+ characters using the given +alphabet+. */
function maxBytesSize(alphabet_size: number, chars_size: number) {
    return Math.floor(Math.log2(alphabet_size) / 8 * chars_size);
}

/**
 * Return the number of bits left over after using an alphabet of the specified +alphabet_size+ to encode a
 * payload of +bytes_size+ with +chars_size+ characters.
 */
function extraBits(alphabet_size: number, chars_size: number, bytes_size: number) {
    const total_bits = Math.floor(Math.log2(alphabet_size) * chars_size);
    return total_bits - 8 * bytes_size;
}

/**
 * Return the +input_bytes+ ascii-armored using the specified +options+
 */
export function armor(input: Uint8Array | string, options?: Partial<Options>): string
export function armor(input: Uint8Array | string, _options?: Partial<Options>) {
    if (!(input instanceof Buffer)) input = Buffer.from(input);
    const options = Object.assign({}, DEFAULT_OPTIONS, _options) as Options;
    if (typeof options.message_type === 'number') options.message_type = modeToStringType(options.message_type);

    const chunks = chunk(input, options.block_size).map(c => Buffer.from(c));

    let output = '';
    for (const chunk of chunks) {
        output += encodeBlock(chunk, options.alphabet, options.shift);
    }

    if (options.raw) {
        const out_chunks = chunk(output, 43).map(c => c.reduce((p, c) => p + c));
        return out_chunks.join(' ');
    }

    const word_chunks = chunk(output, 15).map(c => c.reduce((p, c) => p + c));
    const sentences = chunk(word_chunks, 200);

    const joined = sentences.map(words => words.join(' ')).join('\n');

    const app = options.app_name ? ' ' + options.app_name : '';
    const header = 'BEGIN' + app + ' SALTPACK ' + options.message_type + '. ';
    const footer = '. END' + app + ' SALTPACK ' + options.message_type + '.';

    return header + joined + footer;
}

export class ArmorStream extends Transform {
    readonly armor_options: Readonly<Options>;
    private in_buffer = Buffer.alloc(0);
    private out_buffer = '';
    readonly armor_header: string;
    readonly armor_footer: string;
    private words = 0;

    constructor(options?: Partial<Options>) {
        super();
        this.armor_options = Object.assign({}, DEFAULT_OPTIONS, options);
        if (typeof this.armor_options.message_type === 'number') {
            // @ts-expect-error
            this.armor_options.message_type = modeToStringType(this.armor_options.message_type);
        }

        const app = this.armor_options.app_name ? ' ' + this.armor_options.app_name : '';
        this.armor_header = 'BEGIN' + app + ' SALTPACK ' + this.armor_options.message_type + '. ';
        this.armor_footer = '. END' + app + ' SALTPACK ' + this.armor_options.message_type + '.';

        if (!this.armor_options.raw) {
            this.push(this.armor_header);
        }
    }

    _transform(data: Buffer, encoding: string, callback: TransformCallback) {
        if (debug) console.log('Processing chunk #d: %s', -1, data);

        this.in_buffer = Buffer.concat([this.in_buffer, data]);

        while (this.in_buffer.length > this.armor_options.block_size) {
            const block = this.in_buffer.slice(0, this.armor_options.block_size);
            this.in_buffer = this.in_buffer.slice(this.armor_options.block_size);

            this.out_buffer += encodeBlock(block, this.armor_options.alphabet, this.armor_options.shift);
        }

        if (this.armor_options.raw) {
            while (this.out_buffer.length > 43) {
                this.push(this.out_buffer.substr(0, 43) + ' ');
                this.out_buffer = this.out_buffer.substr(43);
            }
        } else {
            while (this.out_buffer.length > 15) {
                const word = this.out_buffer.substr(0, 15);
                this.out_buffer = this.out_buffer.substr(15);
                this.words++;

                if (this.words >= 200) {
                    this.push(word + '\n');
                    this.words = 0;
                } else {
                    this.push(word + ' ');
                }
            }
        }

        callback();
    }

    _flush(callback: TransformCallback) {
        if (this.in_buffer.length > 0) {
            this.out_buffer += encodeBlock(this.in_buffer, this.armor_options.alphabet, this.armor_options.shift);
            this.in_buffer = Buffer.alloc(0);
        }

        if (this.armor_options.raw) {
            while (this.out_buffer.length > 43) {
                this.push(this.out_buffer.substr(0, 43) + ' ');
                this.out_buffer = this.out_buffer.substr(43);
            }
        } else {
            while (this.out_buffer.length > 15) {
                const word = this.out_buffer.substr(0, 15);
                this.out_buffer = this.out_buffer.substr(15);
                this.words++;

                if (this.words >= 200) {
                    this.push(word + '\n');
                    this.words = 0;
                } else {
                    this.push(word + ' ');
                }
            }
        }

        this.push(this.out_buffer);

        if (!this.armor_options.raw) {
            this.push(this.armor_footer);
        }

        callback();
    }
}

export interface DearmorResult extends Buffer {
    /** Any remaining data after the first armored data */
    remaining: Buffer | null;
    /** The message type and app name included in the header+footer */
    header_info: ArmorHeaderInfo | null;
}
export interface ArmorHeaderInfo {
    /** The message type from the header+footer */
    message_type: MessageType | string;
    /** The application name from the header+footer */
    app_name: string | null;
}

/**
 * Decode the ascii-armored data from the specified +input_chars+ using the given +options+.
 */
export function dearmor(input: Uint8Array | string, options?: Partial<Options>): DearmorResult
export function dearmor(input: Uint8Array | string, _options?: Partial<Options>): DearmorResult {
    if (input instanceof Buffer) input = input.toString();
    if (input instanceof Uint8Array) input = Buffer.from(input).toString();
    const options = Object.assign({}, DEFAULT_OPTIONS, _options);
    let header, header_info: ArmorHeaderInfo | null = null, footer, remaining = null, match;

    if (!options.raw) {
        [header, input, footer, remaining] = input.split('.', 4);
        remaining = Buffer.from(remaining);

        if (!(match = header.match(HEADER_REGEX))) {
            throw new Error('Invalid header');
        }

        header_info = {
            message_type: match[3],
            app_name: match[2] ?? null,
        };

        if (!(match = footer.match(FOOTER_REGEX))) {
            throw new Error('Invalid footer');
        }
        if (header_info.message_type !== match[3] ||
            header_info.app_name != match[2]
        ) {
            throw new Error('Footer doesn\'t match header');
        }
    }
    input = input.replace(/[>\n\r\t ]/g, '');
    const chunks = chunk(input, options.char_block_size).map(c => c.reduce((p, c) => p + c));

    let output = Buffer.alloc(0);
    for (const chunk of chunks) {
        output = Buffer.concat([output, decodeBlock(chunk, options.alphabet, options.shift)]);
    }

    return Object.assign(output, {
        remaining,
        header_info,
    });
}

export class DearmorStream extends Transform {
    readonly armor_options: Readonly<Options>;
    private in_buffer = Buffer.alloc(0);
    private out_buffer = '';
    private armor_header_info: ArmorHeaderInfo | null = null;
    private armor_header: string | null = null;
    private armor_footer: string | null = null;
    private words = 0;

    get header() {
        return this.armor_header;
    }
    get footer() {
        return this.armor_footer;
    }
    get info() {
        return this.armor_header_info;
    }

    constructor(options?: Partial<Options>) {
        super();
        this.armor_options = Object.assign({}, DEFAULT_OPTIONS, options);
    }

    _transform(data: Buffer, encoding: string, callback: TransformCallback) {
        if (debug) console.log('Processing chunk #d: %s', -1, data);

        if (!this.armor_options.raw && this.armor_header === null) {
            this.in_buffer = Buffer.concat([this.in_buffer, data]);

            const index = this.in_buffer.indexOf('.');
            if (index === -1) return callback();

            this.armor_header = this.in_buffer.slice(0, index).toString();
            data = this.in_buffer.slice(index + 1);

            const header_match = this.armor_header.match(HEADER_REGEX);
            if (!header_match) {
                const err = new Error('Invalid header');
                callback(err);
                throw err;
            }

            this.armor_header_info = {
                message_type: header_match[3],
                app_name: header_match[2] ?? null,
            };

            if (debug) console.log('Read header: %s', this.armor_header);
        }

        if (!this.armor_options.raw && this.armor_footer !== null) {
            this.armor_footer += data.toString();

            const remaining_index = this.armor_footer.indexOf('.');
            if (remaining_index !== -1) {
                this.armor_footer = this.armor_footer.substr(0, remaining_index);
                return callback();
            }
        }

        if (!this.armor_options.raw && this.armor_footer === null) {
            const index = data.indexOf('.');
            if (index !== -1) {
                this.armor_footer = data.slice(index + 1).toString();
                data = data.slice(0, index);
                this.out_buffer = data.toString().replace(/[>\n\r\t ]/g, '');

                const remaining_index = this.armor_footer.indexOf('.');
                if (remaining_index !== -1) {
                    this.armor_footer = this.armor_footer.substr(0, remaining_index);
                    return callback();
                }

                return callback();
            }
        }

        if (this.armor_options.raw || this.armor_footer === null) {
            this.out_buffer += data.toString().replace(/[>\n\r\t ]/g, '');

            while (this.out_buffer.length > this.armor_options.char_block_size) {
                const block = this.out_buffer.substr(0, this.armor_options.char_block_size);
                this.out_buffer = this.out_buffer.substr(this.armor_options.char_block_size);

                this.push(decodeBlock(block, this.armor_options.alphabet, this.armor_options.shift));
            }
        }

        callback();
    }

    _flush(callback: TransformCallback) {
        while (this.out_buffer.length > this.armor_options.char_block_size) {
            const block = this.out_buffer.substr(0, this.armor_options.char_block_size);
            this.out_buffer = this.out_buffer.substr(this.armor_options.char_block_size);

            this.push(decodeBlock(block, this.armor_options.alphabet, this.armor_options.shift));
        }

        if (this.out_buffer.length > 0) {
            this.push(decodeBlock(this.out_buffer, this.armor_options.alphabet, this.armor_options.shift));
            this.out_buffer = '';
        }

        if (!this.armor_options.raw && this.armor_footer === null) {
            const err = new Error('Input stream doesn\'t contain a valid header and footer');
            callback(err);
            throw err;
        }

        if (!this.armor_options.raw) {
            const footer_match = this.armor_footer?.match(FOOTER_REGEX);
            if (!footer_match) {
                throw new Error('Invalid footer');
            }
            if (this.armor_header_info!.message_type !== footer_match[3] ||
                this.armor_header_info!.app_name != footer_match[2]
            ) {
                throw new Error('Footer doesn\'t match header');
            }

            if (debug) console.log('Read footer: %s', this.armor_footer);
        }

        callback();
    }
}

/**
 * Encode a single block of ascii-armored output from +bytes_block+ using the specified +alphabet+ and +shift+.
 */
export function encodeBlock(bytes_block: Buffer, alphabet: Alphabet = BASE62_ALPHABET, shift = false): string {
    const block_size = characterBlockSize(alphabet.length, bytes_block.length);
    const extra = extraBits(alphabet.length, block_size, bytes_block.length);

    // Convert the bytes into an integer, big-endian
    let bytes_int = BigInt('0x' + bytes_block.toString('hex'));

    if (shift) {
        let n = 1;
        for (let i = 0; i > extra; i++) n = n * 2;
        bytes_int = bytes_int * BigInt(n);
    }

    const alphabet_size = BigInt(alphabet.length);

    const places = [];
    for (let i = 0; i < block_size; i++) {
        const rem = parseInt((bytes_int % alphabet_size).toString());
        places.unshift(rem);
        bytes_int = bytes_int / alphabet_size;
    }

    return places.map(i => alphabet[i]).join('');
}

/**
 * Decode the specified ascii-armored +chars_block+ using the specified +alphabet+ and +shift+.
 */
export function decodeBlock(chars_block: string, alphabet: Alphabet = BASE62_ALPHABET, shift = false): Buffer {
    const bytes_size = maxBytesSize(alphabet.length, chars_block.length);
    const expected_block_size = characterBlockSize(alphabet.length, bytes_size);

    if (chars_block.length !== expected_block_size) {
        throw new TypeError('Illegal block size ' + chars_block.length + ', expected ' + expected_block_size);
    }

    const extra = extraBits(alphabet.length, chars_block.length, bytes_size);

    let bytes_int: bigint = BigInt(getCharIndex(alphabet, chars_block[0]));

    for (let i = 1; i < chars_block.length; i++) {
        bytes_int = bytes_int * BigInt(alphabet.length);
        bytes_int = bytes_int + BigInt(getCharIndex(alphabet, chars_block[i]));
    }

    if (shift) {
        // TODO
    }
    
    return Buffer.from(bytes_int.toString(16), 'hex');
}

export function efficientCharsSizes(alphabet_size: number, chars_size_upper_bound = 50) {
    const out = [];
    let max_efficiency = 0;

    for (let chars_size = 1; chars_size < chars_size_upper_bound; chars_size++) {
        const bytes_size = maxBytesSize(alphabet_size, chars_size);
        const efficiency = bytes_size / chars_size;

        if (efficiency > max_efficiency) {
            out.push([chars_size, bytes_size, efficiency]);
            max_efficiency = efficiency;
        }
    }

    return out;
}
