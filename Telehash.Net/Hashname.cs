using System;
using System.Collections.Generic;
using System.Diagnostics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Linq;
using System.IO;

namespace Telehash
{
	public class Hashname
	{
		private static char[] trimChars = {'='};

		public Hashname ()
		{
		}

		public static byte[] StringToByteArrayFastest(string hex) {
			if (hex.Length % 2 == 1)
				throw new Exception("The binary key cannot have an odd number of digits");

			byte[] arr = new byte[hex.Length >> 1];

			for (int i = 0; i < hex.Length >> 1; ++i)
			{
				arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
			}

			return arr;
		}

		public static int GetHexVal(char hex) {
			int val = (int)hex;
			//For uppercase A-F letters:
			return val - (val < 58 ? 48 : 55);
			//For lowercase a-f letters:
			//return val - (val < 58 ? 48 : 87);
			//Or the two combined, but a bit slower:
			//return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
		}

		public static string FromKeys(IDictionary<string, string> publicKeys) {
			// You've gotta have some keys to hash!
			if (publicKeys.Count <= 0)
				return null;
			Sha256Digest digest = new Sha256Digest ();
			List<string> keys = new List<string>(publicKeys.Keys);
			keys.Sort ();

			int digestSize = digest.GetDigestSize ();
			byte[] outhash = null;
			foreach (var key in keys) {
				if (outhash != null) {
					digest.BlockUpdate (outhash, 0, digestSize);
				} else {
					outhash = new byte[digestSize];
				}
				byte inByte;
				try {
					inByte = Convert.ToByte (key, 16);
				} catch(FormatException) {
					return null;
				} catch(OverflowException) {
					return null;
				} catch (ArgumentException) {
					return null;
				}
				digest.Update (inByte);
				digest.DoFinal (outhash, 0);
				digest.Reset ();

				digest.BlockUpdate (outhash, 0, digestSize);
				byte[] keyData = Base32Encoder.Decode(publicKeys [key]);
				Sha256Digest keyDigest = new Sha256Digest ();
				keyDigest.BlockUpdate (keyData, 0, keyData.Length);
				keyDigest.DoFinal (outhash, 0);
				digest.BlockUpdate (outhash, 0, outhash.Length);
				digest.DoFinal (outhash, 0);
			}
			return Base32Encoder.Encode (outhash).TrimEnd(trimChars).ToLower();
		}
	}
}

