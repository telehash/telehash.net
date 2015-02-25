using System;
using System.Linq;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Math;

namespace Telehash.E3X
{

	public class CipherSet1a : ICipherSet
	{
		ECKeyPair Key { get; set; }

		public byte CSID {
			get {
				return 0x1a;
			}
		}

		public IKeyPair Keys {
			get {
				return Key;
			}
		}

		public CipherSet1a ()
		{
		}

		public void Generate()
		{
			Key = ECKeyPair.Generate (SecNamedCurves.GetByName ("secp160r1"));
		}

		public void LoadKeys(byte[] publicKeyData, byte[] privateKeyData)
		{
			Key = ECKeyPair.LoadKeys (SecNamedCurves.GetByName ("secp160r1"), publicKeyData, privateKeyData);
		}

		public void GenerateEphemeralKeys(ICipherSetRemoteInfo remoteInfo)
		{
			CS1ARemoteInfo ri = (CS1ARemoteInfo)remoteInfo;
			ri.EphemeralKeys = ECKeyPair.Generate (SecNamedCurves.GetByName ("secp160r1"));
		}

		public Packet MessageEncrypt(ICipherSetRemoteInfo remoteInfo, Packet inner)
		{
			CS1ARemoteInfo ri = (CS1ARemoteInfo)remoteInfo;

			var agreedValue = ECDHAgree (ri.RemotePublicKey, ri.EphemeralKeys.PrivateKey);

			// Hash the agreed key
			var hashedValue = SHA256Hash (agreedValue.ToByteArray ());

			// Fold to get the actual key for AES
			byte[] aesKey = Helpers.Fold (hashedValue);
			Random rnd = new Random ();

			// Setup and encrypt the actual data
			byte[] aesIV = new byte[16];
			rnd.NextBytes (aesIV);
			Array.Clear (aesIV, 4, 12);

			var cipher = new SicBlockCipher (new AesFastEngine ());
			var parameters = new ParametersWithIV (new KeyParameter (aesKey), aesIV);
			cipher.Init (true, parameters);

			var encryptedInner = new byte[inner.FullPacket.Length];
			BufferedBlockCipher bufferCipher = new BufferedBlockCipher (cipher);
			var offset = bufferCipher.ProcessBytes (inner.FullPacket, encryptedInner, 0);
			bufferCipher.DoFinal (encryptedInner, offset);

			// Construct the packet minus the hmac
			Packet outPacket = new Packet ();
			outPacket.Body = new byte[29 + encryptedInner.Length];
			Buffer.BlockCopy (ri.EphemeralKeys.PublicKey, 0, outPacket.Body, 0, ri.EphemeralKeys.PublicKey.Length);
			Buffer.BlockCopy (aesIV, 0, outPacket.Body, 21, 4);
			Buffer.BlockCopy (encryptedInner, 0, outPacket.Body, 25, encryptedInner.Length);

			// ECDH for the hmac key using 
			var idAgreedValue = ECDHAgree (ri.RemotePublicKey, Key.PrivateKey);

			// Mash on the IV for the compound key
			byte[] macKey = new byte[24];
			byte[] idAgreedValueArray = idAgreedValue.ToByteArray();
			Buffer.BlockCopy(idAgreedValueArray, 0, macKey, 0, idAgreedValueArray.Length);
			Buffer.BlockCopy(aesIV, 0, macKey, idAgreedValueArray.Length, 4);

			// Actually hmac all the data now
			var hmac = new HMac (new Sha256Digest ());
			hmac.Init(new KeyParameter (macKey, 0, 24));
			hmac.BlockUpdate(outPacket.Body, 0, 25 + encryptedInner.Length);
			byte[] mac = new byte[hmac.GetMacSize()];
			hmac.DoFinal(mac, 0);

			// Fold it up, shove it in and we're done
			var foldedMac = Helpers.Fold(mac, 3);
			Buffer.BlockCopy(foldedMac, 0, outPacket.Body, 25 + encryptedInner.Length, foldedMac.Length);

			return outPacket;
		}

		public Packet MessageDecrypt(Packet outer)
		{
			byte[] remoteKeyData = outer.Body.Take(21).ToArray();
			byte[] ivData = outer.Body.Skip(21).Take(4).ToArray();
			byte[] innerEncryptedData = outer.Body.Skip(25).Take(outer.Body.Length - 29).ToArray();

			// Decode the body
			ECKeyPair remoteEphemeralKeys = ECKeyPair.LoadKeys (SecNamedCurves.GetByName ("secp160r1"), remoteKeyData, null);

			var idAgreement = ECDHAgree (remoteEphemeralKeys.PublicKey, Key.PrivateKey);
			var agreedHash = SHA256Hash (idAgreement.ToByteArray ());
			var aesKey = Helpers.FoldOnce(agreedHash);

			// Pad out the IV
			byte[] aesIV = new byte[16];
			Array.Clear (aesIV, 0, 16);
			Buffer.BlockCopy (ivData, 0, aesIV, 0, 4);

			// Decrypt it
			var cipher = new BufferedBlockCipher (new SicBlockCipher (new AesFastEngine ()));
			var parameters = new ParametersWithIV (new KeyParameter (aesKey), aesIV);
			cipher.Init (false, parameters);
			byte[] decryptedBody = new byte[innerEncryptedData.Length];
			var offset = cipher.ProcessBytes (innerEncryptedData, decryptedBody, 0);
			cipher.DoFinal (decryptedBody, offset);

			Packet outPacket = Packet.DecodePacket (decryptedBody);

			return outPacket;
		}

		public bool MessageVerify (ICipherSetRemoteInfo remoteInfo, Packet outer)
		{
			CS1ARemoteInfo ri = (CS1ARemoteInfo)remoteInfo;
			byte[] ivData = outer.Body.Skip(21).Take(4).ToArray();
			byte[] hmacData = outer.Body.Skip(outer.Body.Length - 4).Take(4).ToArray();

			// Check the hmac to validate the packet
			var agreedHMacKeyData = ECDHAgree (ri.RemotePublicKey, Key.PrivateKey).ToByteArray ();
			byte[] hmacKey = new byte[24];
			if (agreedHMacKeyData.Length != 20) {
				// It's not a correct agreed value, expected 20 bytes
				return false;
			}
			Buffer.BlockCopy (agreedHMacKeyData, 0, hmacKey, 0, 20);
			Buffer.BlockCopy (ivData, 0, hmacKey, 20, 4);

			var hmac = new HMac (new Sha256Digest ());
			byte[] fullIv = new byte[16];
			Array.Clear (fullIv, 0, 16);
			Buffer.BlockCopy (ivData, 0, fullIv, 0, 4);
			hmac.Init(new KeyParameter (hmacKey, 0, 24));
			hmac.BlockUpdate(outer.Body, 0, outer.Body.Length - 4);
			byte[] mac = new byte[hmac.GetMacSize()];
			hmac.DoFinal(mac, 0);
			var macValue = Helpers.Fold (mac, 3);

			if (!macValue.SequenceEqual (hmacData)) {
				// The hmacs did not match, blow up the world
				return false;
			}

			return true;
		}

		public Packet ChannelEncrypt(ICipherSetChannelInfo channelInfo, Packet inner)
		{
			CS1AChannelInfo ci = (CS1AChannelInfo)channelInfo;

			// TODO:  Validate we don't care about endianess of IV here

			// Setup and encrypt the actual data
			byte[] aesIV = new byte[16];
			Buffer.BlockCopy (BitConverter.GetBytes(ci.IV), 0, aesIV, 0, 4);
			Array.Clear (aesIV, 4, 12);

			var cipher = new SicBlockCipher (new AesFastEngine ());
			var parameters = new ParametersWithIV (new KeyParameter (ci.EncryptionKey), aesIV);
			cipher.Init (true, parameters);

			var encryptedInner = new byte[inner.FullPacket.Length];
			BufferedBlockCipher bufferCipher = new BufferedBlockCipher (cipher);
			var offset = bufferCipher.ProcessBytes (inner.FullPacket, encryptedInner, 0);
			bufferCipher.DoFinal (encryptedInner, offset);

			// Hmac the output
			byte[] hmacKey = new byte[20];
			Buffer.BlockCopy (ci.EncryptionKey, 0, hmacKey, 0, 16);
			Buffer.BlockCopy (BitConverter.GetBytes(ci.IV), 0, hmacKey, 16, 4);

			var hmac = new HMac (new Sha256Digest ());
			hmac.Init(new KeyParameter (hmacKey));
			hmac.BlockUpdate(encryptedInner, 0, encryptedInner.Length);
			byte[] mac = new byte[hmac.GetMacSize()];
			hmac.DoFinal(mac, 0);
			var foldedMac = Helpers.Fold (mac, 3);

			// Create the outgoing packet
			Packet outPacket = new Packet();
			outPacket.Body = new byte[encryptedInner.Length + 24];
			Buffer.BlockCopy(ci.Token, 0, outPacket.Body, 0, 16);
			Buffer.BlockCopy(BitConverter.GetBytes(ci.IV), 0, outPacket.Body, 16, 4);
			Buffer.BlockCopy(encryptedInner, 0, outPacket.Body, 20, encryptedInner.Length);
			Buffer.BlockCopy(foldedMac, 0, outPacket.Body, outPacket.Body.Length - 4, 4);

			// Next IV next packet
			++ci.IV;

			return outPacket;
		}

		public Packet ChannelDecrypt(ICipherSetChannelInfo channelInfo, Packet outer)
		{
			// We gotta have the primary components and something to decrypt
			if (outer.Body.Length < 25) {
				return null;
			}

			CS1AChannelInfo ci = (CS1AChannelInfo)channelInfo;

			// Rip apart our packet
			byte[] token = outer.Body.Take (16).ToArray ();
			byte[] iv = outer.Body.Skip (16).Take (4).ToArray ();
			byte[] encryptedData = outer.Body.Skip (20).Take (outer.Body.Length - 24).ToArray ();
			byte[] dataMac = outer.Body.Skip (outer.Body.Length - 4).Take (4).ToArray ();

			// Make sure we're on the right channel
			if (!token.SequenceEqual (ci.Token)) {
				return null;
			}

			// Validate us some hmac
			byte[] hmacKey = new byte[20];
			Buffer.BlockCopy (ci.DecryptionKey, 0, hmacKey, 0, 16);
			Buffer.BlockCopy (iv, 0, hmacKey, 16, 4);

			var hmac = new HMac (new Sha256Digest ());
			hmac.Init(new KeyParameter (hmacKey));
			hmac.BlockUpdate(encryptedData, 0, encryptedData.Length);
			byte[] mac = new byte[hmac.GetMacSize()];
			hmac.DoFinal(mac, 0);
			var foldedMac = Helpers.Fold (mac, 3);

			if (!foldedMac.SequenceEqual (dataMac)) {
				// Get out of here with your bad data
				return null;
			}

			// Everything seems ok.  Get it decrypted
			byte[] aesIV = new byte[16];
			Buffer.BlockCopy (iv, 0, aesIV, 0, 4);
			Array.Clear (aesIV, 4, 12);

			var cipher = new SicBlockCipher (new AesFastEngine ());
			var parameters = new ParametersWithIV (new KeyParameter (ci.DecryptionKey), aesIV);
			cipher.Init (false, parameters);

			var decryptedData = new byte[encryptedData.Length];
			BufferedBlockCipher bufferCipher = new BufferedBlockCipher (cipher);
			var offset = bufferCipher.ProcessBytes (encryptedData, decryptedData, 0);
			bufferCipher.DoFinal (decryptedData, offset);

			// Build a packet and ship it off
			return Packet.DecodePacket (decryptedData);
		}

		BigInteger ECDHAgree(byte[] publicKey, byte[] privateKey)
		{
			var domain = SecNamedCurves.GetByName ("secp160r1");
			ECDHBasicAgreement agreement = new ECDHBasicAgreement ();
			BigInteger privKeyInt = new BigInteger (privateKey);
			ECDomainParameters parm = new ECDomainParameters(domain.Curve, domain.G, domain.N);
			ECPrivateKeyParameters privKey = new ECPrivateKeyParameters (privKeyInt, parm);
			agreement.Init (privKey);
			var pt = Key.Curve.Curve.DecodePoint (publicKey);
			ECPublicKeyParameters pubParams = new ECPublicKeyParameters (pt, parm);
			return agreement.CalculateAgreement (pubParams);
		}

		byte[] SHA256Hash(byte[] data)
		{
			var shaHash = new Sha256Digest ();
			shaHash.BlockUpdate (data, 0, data.Length);
			byte[] hashedValue = new byte[shaHash.GetDigestSize ()];
			shaHash.DoFinal(hashedValue, 0);
			return hashedValue;
		}
	}

	public class CS1ARemoteInfo : ICipherSetRemoteInfo
	{
		public byte[] RemotePublicKey;
		public byte[] RemoteEphemeralKey;
		public ECKeyPair EphemeralKeys;
	}

	public class CS1AChannelInfo : ICipherSetChannelInfo
	{
		public byte[] Token;
		public uint IV;
		public byte[] EncryptionKey;
		public byte[] DecryptionKey;
	}

}

