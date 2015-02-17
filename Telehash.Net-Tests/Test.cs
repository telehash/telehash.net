using NUnit.Framework;
using System;
using Telehash;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Newtonsoft.Json.Linq;
using Telehash.E3X;

namespace Telehash.NetTests
{
	[TestFixture ()]
	public class Test
	{

		public static byte[] StringToByteArray(string hex) {
			return Enumerable.Range(0, hex.Length)
				.Where(x => x % 2 == 0)
				.Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
				.ToArray();
		}

		[Test ()]
		public void Base32 ()
		{
			byte[] testData = { 0x41, 0x42, 0x43, 0x44 };
			string expectedData = "IFBEGRA=";
			CollectionAssert.AreEqual(expectedData, Base32Encoder.Encode(testData));
		}

		[Test ()]
		public void Hashname ()
		{
			Dictionary<string, string> publicKeys = new Dictionary<string, string> ();
			publicKeys.Add ("1a", "vgjz3yjb6cevxjomdleilmzasbj6lcc7");
			publicKeys.Add ("3a", "hp6yglmmqwcbw5hno37uauh6fn6dx5oj7s5vtapaifrur2jv6zha");
			Assert.AreEqual("jvdoio6kjvf3yqnxfvck43twaibbg4pmb7y3mqnvxafb26rqllwa", Telehash.Hashname.FromKeys (publicKeys));

			publicKeys.Clear ();
			publicKeys.Add ("1a", "vgjz3yjb6cevxjomdleilmzasbj6lcc7");
			Assert.AreEqual("echmb6eke2f6z2mqdwifrt6i6hkkfua7hiisgrms6pwttd6jubiq", Telehash.Hashname.FromKeys(publicKeys));
		
			publicKeys.Clear ();
			publicKeys.Add ("bad", "echmb6eke2f6z2mqdwifrt6i6hkkfua7hiisgrms6pwttd6jubiq");
			Assert.IsNull (Telehash.Hashname.FromKeys (publicKeys));

			publicKeys.Clear ();
			Assert.IsNull (Telehash.Hashname.FromKeys (publicKeys));
		}

		[Test()]
		public void Packet()
		{
			// Basic packet decoding
			byte[] packetData = StringToByteArray ("001d7b2274797065223a2274657374222c22666f6f223a5b22626172225d7d616e792062696e61727921");
			Telehash.E3X.Packet p = new Telehash.E3X.Packet (packetData);
			Assert.AreEqual (p.HeadLength, 29);
			Assert.AreEqual (p.Body.Length, 11);
			Assert.AreEqual ((string)p.Head ["type"], "test");
			Assert.AreEqual ((string)p.Head ["foo"] [0], "bar");

			Telehash.E3X.Packet encodeTestPacket = new Telehash.E3X.Packet ();
			encodeTestPacket.Body = p.Body;
			encodeTestPacket.Head.Add ("type", "test");
			var fooArray = new JArray ();
			fooArray.Add ("bar");
			encodeTestPacket.Head.Add ("foo", fooArray);
			encodeTestPacket.Encode ();
			Assert.AreEqual (packetData, encodeTestPacket.FullPacket);
		}

		[Test()]
		public void Folding()
		{
			byte[] testData = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
			byte[] outData = Helpers.Fold (testData);
			byte[] expectedData = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
			Assert.AreEqual(outData, expectedData);

			byte[] expectedData2 = { 0x05, 0x07, 0x05 };
			byte[] outData2 = Helpers.Fold (testData, 2);
			Assert.AreEqual (outData2, expectedData2);
		}

		[Test()]
		public void CS1A()
		{

		}

		[Test()]
		public void Handshake()
		{
			byte[] A_KEY = Telehash.Base32Encoder.Decode("anfpjrveyyloypswpqzlfkjpwynahohffy");
			byte[] A_SEC = Telehash.Base32Encoder.Decode("cgcsbs7yphotlb5fxls5ogy2lrc7yxbg");
			byte[] B_KEY = Telehash.Base32Encoder.Decode("amhofcnwgmolf3owg2kipr5vus7uifydsy");
			byte[] B_SEC = Telehash.Base32Encoder.Decode("ge4i7h3jln4kltngwftg2yqtjjvemerw");

			Self localSelf = new Self ();
			CipherSet1a cs = new CipherSet1a ();
			cs.LoadKeys (A_KEY, A_SEC);
			localSelf.CipherSets.Add(0x1a, cs);

			Exchange ex = new Exchange (localSelf, 0x1a, B_KEY);
			var outPacket = ex.Handshake (0x1a);
			Console.Write (outPacket);


			Self remoteSelf = new Self ();
			CipherSet1a remoteCs = new CipherSet1a ();
			remoteCs.LoadKeys (B_KEY, B_SEC);
			remoteSelf.CipherSets.Add (0x1a, remoteCs);
			CS1ARemoteInfo ri = new CS1ARemoteInfo ();
			ri.RemotePublicKey = A_KEY;
			var decryptedPacket = remoteCs.MessageDecrypt (ri, outPacket);

			System.Diagnostics.Debug.Write (decryptedPacket);
		}
	}
}

