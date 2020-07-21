node-saltpack
===

A Node.js/TypeScript implementation of [Keybase](https://keybase.io)'s [Saltpack](https://saltpack.org)
encrypted/signed messaging format.

node-saltpack implements version 2.0 of Saltpack. All message types (encryption, attached signing,
detached signing and signcryption) are supported.

Installation
---

node-saltpack is published to the npm registry and GitHub Package Registry. TypeScript definitions are included.

```
npm install @samuelthomas2774/saltpack
```

### GitHub Package Registry

By default npm will install from https://npmjs.com. You can configure npm to install node-saltpack from
GitHub Package Registry by adding this to your npmrc:

```
@samuelthomas2774:registry=https://npm.pkg.github.com
```
```
echo "@samuelthomas2774:registry=https://npm.pkg.github.com" >> `npm --global prefix`/etc/npmrc
```

Encryption
---

`encryptAndArmor` encrypts a string or Uint8Array (or a Node.js Buffer) and returns the ASCII-armored encrypted
data as a string.

`encrypt` accepts the same arguments as `encryptAndArmor` but returns a Buffer without armor.

```ts
import {encryptAndArmor} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const plaintext: Buffer | string = '...';
const sender_keypair: tweetnacl.BoxKeyPair = tweetnacl.box.keyPair();
const recipients_keys: Uint8Array[] = [
    tweetnacl.box.keyPair().publicKey,
];

const encrypted = await encryptAndArmor(plaintext, sender_keypair, recipients_keys);

// encrypted === 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P ...
```

node-saltpack also supports streaming encryption with `EncryptAndArmorStream` or (`EncryptStream` for encrypting
without armor).

```ts
import {EncryptAndArmorStream} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const sender_keypair: tweetnacl.BoxKeyPair = tweetnacl.box.keyPair();
const recipients_keys: Uint8Array[] = [
    tweetnacl.box.keyPair().publicKey,
];

const stream = new EncryptAndArmorStream(sender_keypair, recipients_keys);

stream.end('...');

// Write the encrypted and armored data to stdout
stream.pipe(process.stdout);
```

Messages can be decrypted with `dearmorAndDecrypt` (or `decrypt` if the message isn't armored).

```ts
import {dearmorAndDecrypt} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const encrypted: string = 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P ...';
const recipient_keypair: tweetnacl.BoxKeyPair = tweetnacl.box.keyPair();

// If you know the sender's public key you can pass it to dearmorAndDecrypt and it will throw if it doesn't match
const sender_key: Uint8Array = tweetnacl.box.keyPair().publicKey;

try {
    const decrypted = await dearmorAndDecrypt(encrypted, recipient_keypair, sender_key);

    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(decrypted.sender_public_key).equals(sender_keys)) {
        throw new Error('Sender public key doesn\'t match');
    }

    // decrypted === '...'
} catch (err) {
    console.error(err);
}
```

Decryption also supports streaming with `DearmorAndDecryptStream` or `DecryptStream`.

```ts
import {DearmorAndDecryptStream} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const recipient_keypair: tweetnacl.BoxKeyPair = tweetnacl.box.keyPair();

// If you know the sender's public key you can pass it to DearmorAndDecryptStream and it will emit an error if it doesn't match
const sender_key: Uint8Array = tweetnacl.box.keyPair().publicKey;

const stream = new DearmorAndDecryptStream(recipient_keypair, sender_key);

stream.on('end', () => {
    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(stream.sender_public_key).equals(sender_keys)) {
        throw new Error('Sender public key doesn\'t match');
    }
});
stream.on('error', err => {
    console.error(err);
});

stream.end('BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeD305h3lDop TELGyPzBAAawRfZ rss3XwjQHK0irv7 rNIcmnvmn5YlTtK 7O1fFPePZGpx46P ...');

// Write the decrypted data to stdout
stream.pipe(process.stdout);
```

Signing
---

`signAndArmor` signs a string or Uint8Array (or a Node.js Buffer) and returns the ASCII-armored signed data as a
string.

`sign` accepts the same arguments as `signAndArmor` but returns a Buffer without armor.

```ts
import {signAndArmor} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const plaintext: Buffer | string = '...';
const signing_keypair: tweetnacl.SignKeyPair = tweetnacl.sign.keyPair();

const signed = await signAndArmor(plaintext, signing_keypair);

// signed === 'BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...
```

Streaming is supported with `SignAndArmorStream` or `SignStream`.

```ts
import {SignAndArmorStream} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const signing_keypair: tweetnacl.SignKeyPair = tweetnacl.sign.keyPair();

const stream = new SignAndArmorStream(signing_keypair);

stream.end('...');

// Write the signed and armored data to stdout
stream.pipe(process.stdout);
```

Signed messages can be verified and read with `dearmorAndVerify` or `verify`.

```ts
import {dearmorAndVerify} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const signed: string = 'BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...';

// If you know the sender's public key you can pass it to dearmorAndVerify and it will throw if it doesn't match
const sender_key: Uint8Array = tweetnacl.sign.keyPair().publicKey;

try {
    const verified = await dearmorAndVerify(signed, sender_key);

    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(verified.public_key).equals(sender_key)) {
        throw new Error('Sender public key doesn\'t match');
    }

    // verified === '...'
} catch (err) {
    console.error(err);
}
```

Reading signed messages also supports streaming with `DearmorAndVerifyStream` or `VerifyStream`.

```ts
import {DearmorAndVerifyStream} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

// If you know the sender's public key you can pass it to DearmorAndVerifyStream and it will emit an error if it doesn't match
const sender_key: Uint8Array = tweetnacl.sign.keyPair().publicKey;

const stream = new DearmorAndVerifyStream(recipient_keypair, sender_key);

stream.on('end', () => {
    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(stream.public_key).equals(sender_keys)) {
        throw new Error('Sender public key doesn\'t match');
    }
});
stream.on('error', err => {
    console.error(err);
});

stream.end('BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...');

// Write the decrypted data to stdout
stream.pipe(process.stdout);
```

Detaching signing
---

`signDetachedAndArmor` signs a string or Uint8Array (or a Node.js Buffer) and returns the ASCII-armored signature
as a string.

`signDetached` accepts the same arguments as `signDetachedAndArmor` but returns a Buffer without armor.

> Detached signing/verifying does not support streaming yet.

```ts
import {signDetachedAndArmor} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const plaintext: Buffer | string = '...';
const signing_keypair: tweetnacl.SignKeyPair = tweetnacl.sign.keyPair();

const signed = await signDetachedAndArmor(plaintext, signing_keypair);

// signed === 'BEGIN SALTPACK DETACHED SIGNATURE. kYM5h1pg6qz9UMn j6G9T0tZQlxoky3 0YoKQ4s21IrFv3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...
```

Detached signatures can be verified with `dearmorAndVerifyDetached` or `verifyDetached`.

```ts
import {dearmorAndVerifyDetached} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const signed: string = 'BEGIN SALTPACK SIGNED MESSAGE. kYM5h1pg6qz9UMn j6G9T0lmMjkYOsZ Kn4Acw58u39dn3B kmdpuvqpO3t2QdM CnBX5wO1ZIO8LTd knNlCR0WSEC0000 ...';
const plaintext: Buffer | string = '...';

// If you know the sender's public key you can pass it to dearmorAndVerifyDetached and it will throw if it doesn't match
const sender_key: Uint8Array = tweetnacl.sign.keyPair().publicKey;

try {
    const result = await dearmorAndVerifyDetached(signature, plaintext, sender_key);

    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(result.public_key).equals(sender_key)) {
        throw new Error('Sender public key doesn\'t match');
    }
} catch (err) {
    console.error(err);
}
```

Signcryption
---

> Signcryption is very similar to Saltpack's usual encryption format, but:
>
> - The sender uses an Ed25519 signing key instead of an X25519 encryption key,
> - A symmetric key can be provided for a group of recipients instead of each recipient having their own encryption
>     key (this is not implemented by node-saltpack yet, though the internal APIs are there), and
> - Messages are not repudiable, which means anyone who has a copy of the message and a decryption key can verify it's
>     authenticity, not just intended recipients.

`signcryptAndArmor` encrypts a string or Uint8Array (or a Node.js Buffer) and returns the ASCII-armored signcrypted
data as a string.

`signcrypt` accepts the same arguments as `signcryptAndArmor` but returns a Buffer without armor.

```ts
import {signcryptAndArmor} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const plaintext: Buffer | string = '...';
const sender_keypair: tweetnacl.SignKeyPair = tweetnacl.sign.keyPair();
const recipients_keys: Uint8Array[] = [
    // TODO: how can a recipient identifier and symmetric key be provided?
    tweetnacl.box.keyPair().publicKey,
];

const signcrypted = await signcryptAndArmor(plaintext, sender_keypair, recipients_keys);

// signcrypted === 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHnhYI5G UXZkLqLqVvhmpfZ rss3XwjQHK0irv7 rNIcmnvmn5RTzTR OPZLLRr1s0DEZtS ...
```

Streaming is supported with `SigncryptAndArmorStream` or (`SigncryptStream` for encrypting without armor).

```ts
import {SigncryptAndArmorStream} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const sender_keypair: tweetnacl.SignKeyPair = tweetnacl.sign.keyPair();
const recipients_keys: Uint8Array[] = [
    // TODO: how can a recipient identifier and symmetric key be provided?
    tweetnacl.box.keyPair().publicKey,
];

const stream = new SigncryptAndArmorStream(sender_keypair, recipients_keys);

stream.end('...');

// Write the signcrypted and armored data to stdout
stream.pipe(process.stdout);
```

Messages can be decrypted with `dearmorAndDesigncrypt` (or `designcrypt` if the message isn't armored).

```ts
import {dearmorAndDesigncrypt} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

const encrypted: string = 'BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHnhYI5G UXZkLqLqVvhmpfZ rss3XwjQHK0irv7 rNIcmnvmn5RTzTR OPZLLRr1s0DEZtS ...';
// TODO: how can a recipient identifier and symmetric key be provided?
// How can multiple keys be provided (as a recipient may have multiple shared symmetric keys that may be used for this message)
const recipient_keypair: tweetnacl.BoxKeyPair = tweetnacl.box.keyPair();

// If you know the sender's public key you can pass it to dearmorAndDesigncrypt and it will throw if it doesn't match
const sender_key: Uint8Array = tweetnacl.sign.keyPair().publicKey;

try {
    const decrypted = await dearmorAndDesigncrypt(encrypted, recipient_keypair, sender_key);

    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(decrypted.sender_public_key).equals(sender_keys)) {
        throw new Error('Sender public key doesn\'t match');
    }

    // decrypted === '...'
} catch (err) {
    console.error(err);
}
```

Decryption also supports streaming with `DearmorAndDesigncryptStream` or `DesigncryptStream`.

```ts
import {DearmorAndDesigncryptStream} from '@samuelthomas2774/saltpack';
import * as tweetnacl from 'tweetnacl';

// TODO: how can a recipient identifier and symmetric key be provided?
// How can multiple keys be provided (as a recipient may have multiple shared symmetric keys that may be used for this message)
const recipient_keypair: tweetnacl.BoxKeyPair = tweetnacl.box.keyPair();

// If you know the sender's public key you can pass it to DearmorAndDesigncryptStream and it will emit an error if it doesn't match
const sender_key: Uint8Array = tweetnacl.sign.keyPair().publicKey;

const stream = new DearmorAndDesigncryptStream(recipient_keypair, sender_key);

stream.on('end', () => {
    // If you didn't pass the sender's public key you should check it now
    if (!Buffer.from(stream.sender_public_key).equals(sender_keys)) {
        throw new Error('Sender public key doesn\'t match');
    }
});
stream.on('error', err => {
    console.error(err);
});

stream.end('BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHnhYI5G UXZkLqLqVvhmpfZ rss3XwjQHK0irv7 rNIcmnvmn5RTzTR OPZLLRr1s0DEZtS ...');

// Write the decrypted data to stdout
stream.pipe(process.stdout);
```

Additional notes
---

- node-saltpack always chunks input data to 1 MB payloads.
- node-saltpack is fully tested with [php-saltpack](https://gitlab.fancy.org.uk/samuel/php-saltpack).
- node-saltpack is partially tested with [Keybase](https://github.com/keybase/saltpack):
    - Encrypted messages created by node-saltpack and php-saltpack can be decrypted with Keybase.
    - Signcrypted messages created by node-saltpack and php-saltpack can be decrypted with Keybase.
    - Signed messages created by Keybase can be verified with node-saltpack and php-saltpack.
    - Signed messages created by node-saltpack and php-saltpack can be read by Keybase.

License
---

node-saltpack is released under the [MIT license](LICENSE). Saltpack is designed by the Keybase developers,
and uses [NaCl](https://nacl.cr.yp.to) for crypto and [MessagePack](https://msgpack.org) for binary encoding.
node-saltpack uses [TweetNaCl.js](https://tweetnacl.js.org). node-saltpack and php-saltpack's armoring
implementation is based on [saltpack-ruby](https://github.com/ged/saltpack-ruby).
