using System;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace Telehash.E3X
{
	public class ECKeyPair : IKeyPair
	{
		private static SecureRandom secureRandom = new SecureRandom ();

		private BigInteger priv;
		private byte[] pub;

		public X9ECParameters Curve;
		public ECDomainParameters Domain;

		public static ECKeyPair LoadKeys (X9ECParameters curve, byte[] publicKeyData, byte[] privateKeyData)
		{
			ECKeyPair k = new ECKeyPair ();
			k.Curve = curve;
			if (privateKeyData != null) {
				k.priv = new BigInteger (privateKeyData);
			}
			k.pub = publicKeyData;
			return k;
		}

		public static ECKeyPair Generate (X9ECParameters curve, bool compressed = true)
		{
			ECKeyPairGenerator generator = new ECKeyPairGenerator ();
			ECDomainParameters newDomain = new ECDomainParameters(curve.Curve, curve.G, curve.N);
			ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters (newDomain, secureRandom);
			generator.Init (keygenParams);
			var keyPair = generator.GenerateKeyPair ();
			ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keyPair.Private;
			ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keyPair.Public;
			ECKeyPair k = new ECKeyPair ();
			k.Domain = newDomain;
			k.Curve = curve;
			k.priv = privParams.D;
			k.pub = pubParams.Q.GetEncoded (compressed);
			return k;
		}

		public byte[] PublicKey {
			get {
				return pub;
			}
		}

		public byte[] PrivateKey {
			get {
				return priv.ToByteArray ();
			}
		}
	}
}

