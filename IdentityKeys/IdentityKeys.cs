using System;
using System.Security.Cryptography;
using Base58Check;
using Chaos.NaCl;

namespace IdentityKeys
{
    public class PrivateIdentityKey
    {
        public static readonly byte[] PREFIX = new byte[] { 0x03, 0x45, 0xf3, 0xd0, 0xd6 };
        public byte[] Seed { get; set; }

        public PrivateIdentityKey()
        {
            Seed = new byte[32];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(Seed);
        }

        public PrivateIdentityKey(byte[] seed)
        {
            if (seed == null) {
                throw new System.ArgumentException("Parameter cannot be null", "seed");
            }
            else if (seed.Length != 32)
            {
                throw new System.ArgumentException("Parameter must be 32 bytes long", "seed");
            }
            Seed = seed;
        }

        public PrivateIdentityKey(string keyString)
        {
            if (keyString == null) {
                throw new System.ArgumentException("Parameter cannot be null", "keyString");
            }
            else if (keyString.Length != 55 || keyString.Substring(0, 5) != "idsec")
            {
                throw new System.ArgumentException("Invalid private key string", "keyString");
            }
            byte[] withPrefix;
            try
            {
                withPrefix = Base58CheckEncoding.Decode(keyString);
            }
            catch (FormatException)
            {
                throw new System.ArgumentException("Invalid private key string", "keyString");
            }
            Seed = new byte[32];
            System.Buffer.BlockCopy(withPrefix, PrivateIdentityKey.PREFIX.Length, Seed, 0, Seed.Length);
        }
        
        public PublicIdentityKey GetPublicIdentityKey()
        {
            return new PublicIdentityKey(Ed25519.PublicKeyFromSeed(Seed));
        }

        public byte[] Sign(byte[] message)
        {
            return Ed25519.Sign(message, Ed25519.ExpandedPrivateKeyFromSeed(Seed));
        }

        override public string ToString()
        {
            byte[] withPrefix = new byte[PrivateIdentityKey.PREFIX.Length + Seed.Length];
            System.Buffer.BlockCopy(PrivateIdentityKey.PREFIX, 0, withPrefix, 0, PrivateIdentityKey.PREFIX.Length);
            System.Buffer.BlockCopy(Seed, 0, withPrefix, PrivateIdentityKey.PREFIX.Length, Seed.Length);
            return Base58CheckEncoding.Encode(withPrefix);
        }
    }

    public class PublicIdentityKey
    {
        public static readonly byte[] PREFIX = new byte[] { 0x03, 0x45, 0xef, 0x9d, 0xe0 };
        public byte[] Bytes { get; set; }

        public PublicIdentityKey(byte[] bytes)
        {
            if (bytes == null) {
                throw new System.ArgumentException("Parameter cannot be null", "bytes");
            }
            else if (bytes.Length != 32)
            {
                throw new System.ArgumentException("Parameter must be 32 bytes long", "bytes");
            }
            Bytes = bytes;
        }

        public PublicIdentityKey(string keyString) {
            if (keyString == null) {
                throw new System.ArgumentException("Parameter cannot be null", "keyString");
            }
            else if (keyString.Length != 55 || keyString.Substring(0, 5) != "idpub")
            {
                throw new System.ArgumentException("Invalid public key string", "keyString");
            }
            byte[] withPrefix;
            try
            {
                withPrefix = Base58CheckEncoding.Decode(keyString);
            }
            catch (FormatException)
            {
                throw new System.ArgumentException("Invalid public key string", "keyString");
            }
            Bytes = new byte[32];
            System.Buffer.BlockCopy(withPrefix, PublicIdentityKey.PREFIX.Length, Bytes, 0, Bytes.Length);
        }

        public bool Verify(byte[] message, byte[] signature)
        {
            return Ed25519.Verify(signature, message, Bytes);
        }

        override public string ToString()
        {
            byte[] keyBody = new byte[PublicIdentityKey.PREFIX.Length + Bytes.Length];
            System.Buffer.BlockCopy(PublicIdentityKey.PREFIX, 0, keyBody, 0, PublicIdentityKey.PREFIX.Length);
            System.Buffer.BlockCopy(Bytes, 0, keyBody, PublicIdentityKey.PREFIX.Length, Bytes.Length);
            return Base58CheckEncoding.Encode(keyBody);
        }
    }
}
