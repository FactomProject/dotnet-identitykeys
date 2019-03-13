# .NET Identity Keys

A small module of tools to generate and use key pairs for Factom Identities.

## Usage
Install this package from nuget: https://www.nuget.org/packages/IdentityKeys

Generating a new random key pair and getting the idpub/idec key strings:
```csharp
PrivateIdentityKey priv = new PrivateIdentityKey();
PublicIdentityKey pub = priv.GetPublicIdentityKey();
Console.WriteLine("Private Key: " + priv.ToString());
Console.WriteLine("Public Key: " + pub.ToString());
```

Signing a message and then verifying the signature:
```csharp
PrivateIdentityKey priv = new PrivateIdentityKey();
PublicIdentityKey pub = priv.GetPublicIdentityKey();
byte[] message = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
byte[] signature = priv.Sign(message);

if (pub.Verify(message, signature))
    Console.WriteLine("Signature Valid!");
else
    Console.WriteLine("Signature Invalid!");
```

## Format of an Identity Key Pair
*Note: the following text is taken from the [Application Identity Specification](https://github.com/FactomProject/FactomDocs/blob/FD-849_PublishNewIdentitySpec/ApplicationIdentity.md)*

For Factom Application Identities, ed25519 keys are used to sign and verify messages. Rather than simply using raw 32 byte arrays for keys, the following encoding scheme is used: 

Pseudo-code for constructing a private key string:
```
prefix_bytes = [0x03, 0x45, 0xf3, 0xd0, 0xd6]              // gives an "idsec" prefix once in base58 
key_bytes = [32 bytes of raw private key]                  // the actual ed25519 private key seed
checksum = sha256( sha256(prefix_bytes + key_bytes) )[:4]  // 4 byte integrity check on the previous 37 bytes

idsec_key_string = base58( prefix_bytes + key_bytes + checksum )
```

Pseudo-code for constructing a public key string:
```
prefix_bytes = [0x03, 0x45, 0xef, 0x9d, 0xe0]              // gives an "idpub" prefix once in base58 
key_bytes = [32 bytes of raw public key]                   // the actual ed25519 public key
checksum = sha256( sha256(prefix_bytes + key_bytes) )[:4]  // 4 byte integrity check on the previous 37 bytes

idpub_key_string = base58( prefix_bytes + key_bytes + checksum )
```

For the sake of human-readability, all characters must be in Bitcoin's base58 character set, the private key will always begin with "idsec", and the public key will always begin with "idpub". Additionally, the checksum at the end serves to signal that a user has incorrectly typed/copied their key.

Example key pair for the private key of all zeros:
- `idsec19zBQP2RjHg8Cb8xH2XHzhsB1a6ZkB23cbS21NSyH9pDbzhnN6 idpub2Cy86teq57qaxHyqLA8jHwe5JqqCvL1HGH4cKRcwSTbymTTh5n`

Example key pair for the private key of all ones:
- `idsec1ARpkDoUCT9vdZuU3y2QafjAJtCsQYbE2d3JDER8Nm56CWk9ix idpub2op91ghJbRLrukBArtxeLJotFgXhc6E21syu3Ef8V7rCcRY5cc`