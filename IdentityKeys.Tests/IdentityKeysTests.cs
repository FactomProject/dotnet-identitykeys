using NUnit.Framework;
using System;
using IdentityKeys;

namespace Tests
{
    public class IdentityKeysTests
    {
        
        string zerosSecret = "idsec19zBQP2RjHg8Cb8xH2XHzhsB1a6ZkB23cbS21NSyH9pDbzhnN6";
        string zerosPublic = "idpub2Cy86teq57qaxHyqLA8jHwe5JqqCvL1HGH4cKRcwSTbymTTh5n";
        byte[] zeros = new byte[PrivateIdentityKey.SEED_LENGTH];

        [Test]
        public void ConstructorThrowsExceptionOnInvalidInput()
        {
            byte[] nullBytes = null;
            string nullString = null;
            Assert.Throws<ArgumentException>(delegate { new PrivateIdentityKey(nullBytes); });
            Assert.Throws<ArgumentException>(delegate { new PublicIdentityKey(nullBytes); });
            Assert.Throws<ArgumentException>(delegate { new PrivateIdentityKey(nullString); });
            Assert.Throws<ArgumentException>(delegate { new PublicIdentityKey(nullString); });

            // Bad length byte array
            Assert.Throws<ArgumentException>(delegate { new PrivateIdentityKey(new byte[33]); });
            Assert.Throws<ArgumentException>(delegate { new PublicIdentityKey(new byte[33]); });

            // Completely invalid string
            Assert.Throws<ArgumentException>(delegate { new PrivateIdentityKey("invalid"); });
            Assert.Throws<ArgumentException>(delegate { new PublicIdentityKey("invalid"); });

            // Bad checksum
            string badSecret = "idsec19zBQP2RjHg8Cb8xH2XHzhsB1a6ZkB23cbS21NSyH9pDbzhnXX";
            string badPublic = "idpub2Cy86teq57qaxHyqLA8jHwe5JqqCvL1HGH4cKRcwSTbymTThXX";
            Assert.Throws<ArgumentException>(delegate { new PrivateIdentityKey(badSecret); });
            Assert.Throws<ArgumentException>(delegate { new PublicIdentityKey(badPublic); });

            // Swap public and private
            Assert.Throws<ArgumentException>(delegate { new PrivateIdentityKey(zerosPublic); });
            Assert.Throws<ArgumentException>(delegate { new PublicIdentityKey(zerosSecret); });
        }

        [Test]
        public void ToStringGivesSameKeyAsCreatedWith()
        {
            PrivateIdentityKey priv = new PrivateIdentityKey(zerosSecret);
            PublicIdentityKey pub = new PublicIdentityKey(zerosPublic);
            Assert.AreEqual(zerosSecret, priv.ToString());
            Assert.AreEqual(zerosPublic, pub.ToString());
        }

        [Test]
        public void GetPublicIdentityKeyGivesExpectedZerosKey()
        {
            PrivateIdentityKey priv = new PrivateIdentityKey(zerosSecret);
            PublicIdentityKey pub = priv.GetPublicIdentityKey();
            Assert.AreEqual(zerosPublic, pub.ToString());
        }

        [Test]
        public void SignedMessageCanBeVerified()
        {
            PrivateIdentityKey priv = new PrivateIdentityKey();
            PublicIdentityKey pub = priv.GetPublicIdentityKey();
            byte[] message = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
            byte[] signature = priv.Sign(message);
            Assert.True(pub.Verify(message, signature));
        }

        [Test]
        public void VerifyBadSignatureReturnsFalse()
        {
            PrivateIdentityKey priv = new PrivateIdentityKey();
            PublicIdentityKey pub = priv.GetPublicIdentityKey();
            byte[] message = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
            byte[] signature = priv.Sign(message);
            Assert.False(pub.Verify(message, new byte[64])); // Bad signature
            Assert.False(pub.Verify(new byte[5], signature)); // Bad message
            Assert.False(pub.Verify(new byte[5], new byte[64])); // Bad both
        }
        
    }
}