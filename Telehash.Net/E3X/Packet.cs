using System;
using System.Net;
using System.Linq;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Telehash.E3X
{
	public class Packet
	{
		// Sha256("telehash")
		static private byte[] cloakKey = {
			0xd7, 0xf0, 0xe5, 0x55, 0x54, 0x62, 0x41, 0xb2, 
			0xa9, 0x44, 0xec, 0xd6, 0xd0, 0xde, 0x66, 0x85, 
			0x6a, 0xc5, 0x0b, 0x0b, 0xab, 0xa7, 0x6a, 0x6f,
			0x5a, 0x47, 0x82, 0x95, 0x6c, 0xa9, 0x45, 0x9a
		};

		/// <summary>
		/// If this Packet was inside another Packet's Body, or decrypted from another Packet, this is the parent Packet.
		/// </summary>
		/// <value>The parent Packet instance.</value>
		public Packet Parent { get; set; }
		public ushort HeadLength { get; set; }
		public byte[] FullPacket { get; set; }
		public JObject Head { get; set; }
		public byte[] HeadBytes { get; set; }
		public ushort BodyLength { get; set; }
		public byte[] Body {
			get {
				if (FullPacket == null || FullPacket.Length == 0)
					return NewBody;
				return FullPacket.Skip (HeadLength + 2).Take (BodyLength).ToArray ();
			}

			set {
				NewBody = value;
			}
		}
		private byte[] NewBody;

		public Packet ()
		{
			Head = new JObject ();
			FullPacket = null;
		}

		public Packet(byte[] packetData)
		{
			Decode (packetData);
		}

		public static Packet DecodePacket(byte[] packetData)
		{
			Packet pkt = new Packet();
			if (!pkt.Decode(packetData)) {
				return null;
			}
			return pkt;
		}

		/// <summary>
		/// Decode the packet data into the fields of the class.
		/// </summary>
		/// <param name="packetData">Packet data.</param>
		public bool Decode(byte[] packetData)
		{
			// Gotta have a length!
			if (packetData.Length < 2) {
				return false;
			}

			short tmp = BitConverter.ToInt16 (packetData, 0);
			HeadLength = (ushort)IPAddress.NetworkToHostOrder(tmp);
			BodyLength = (ushort)(packetData.Length - HeadLength - 2);

			if (HeadLength > packetData.Length || (HeadLength + BodyLength > packetData.Length)) {
					return false;
			}

			FullPacket = packetData;

			if (HeadLength >= 7) {
				string jsonData = System.Text.Encoding.UTF8.GetString (packetData.Skip (2).Take (HeadLength).ToArray ());
				Head = JObject.Parse (jsonData);
			} else if (HeadLength > 0) {
				HeadBytes = packetData.Skip (2).Take (HeadLength).ToArray ();
			}

			return true;
		}

		public void Encode()
		{

			byte[] jsonHead = Encoding.UTF8.GetBytes(Head.ToString (Newtonsoft.Json.Formatting.None));
			if (Head.Count != 0) {
				HeadLength = (ushort)jsonHead.Length;
			}
			BodyLength = NewBody != null ? (ushort)NewBody.Length : (ushort)0;
			FullPacket = new byte[HeadLength + BodyLength + 2];
			MemoryStream ms = new MemoryStream (FullPacket);
			BinaryWriter bw = new BinaryWriter (ms);
			short hl = IPAddress.HostToNetworkOrder ((short)HeadLength);
			bw.Write (hl);
			if (HeadLength >= 7) {
				bw.Write (jsonHead);
			} else if (HeadLength > 0 && HeadLength < 6) {
				bw.Write (HeadBytes);
			}
			if (NewBody.Length > 0) bw.Write (NewBody);
			ms.Close ();
		}

		public string ToDebugString()
		{
			StringBuilder sb = new StringBuilder ();
			sb.AppendLine ("Packet\n======");
			sb.AppendFormat ("Head Length: {0}\n", HeadLength);
			if (HeadLength < 7 && HeadLength > 0) {
				sb.AppendFormat ("Head: {0}\n", Helpers.ToHexSring (HeadBytes));
			} else if (HeadLength > 7 && Head != null) {
				sb.AppendLine ("Head:");
				foreach (var entry in Head) {
					sb.AppendFormat ("\t {0}: {1}\n", entry.Key, entry.Value);
				}
			}
			if (Body != null) {
				sb.AppendFormat ("Body: {0}\n", Helpers.ToHexSring (Body));
			}
			sb.AppendFormat ("Raw: {0}\n", Helpers.ToHexSring(FullPacket));
			return sb.ToString ();
		}

		/// <summary>
		/// Decloak the given buffer and return the valid Packet from it
		/// </summary>
		/// <param name="buffer">A cloaked packet buffer.</param>
		static public Packet Decloak(byte[] buffer)
		{
			if (buffer.Length < 8 || buffer [0] == 0) {
				return Packet.DecodePacket (buffer);
			}

			byte[] nonce = buffer.Take (8).ToArray ();
			var parms = new ParametersWithIV(new KeyParameter(cloakKey), nonce);

			var chacha = new ChaChaEngine(20);
			chacha.Init(false, parms);
			byte[] outBuff = new byte[buffer.Length - 8];
			chacha.ProcessBytes(buffer, 8, buffer.Length - 8, outBuff, 0);

			return Decloak (outBuff);
		}

		public byte[] Cloak()
		{
			Encode ();

			byte[] outData = new byte[FullPacket.Length + 8];

			// Get our nonce
			Random rnd = new Random ();
			byte[] nonce = new byte[8];
			rnd.NextBytes (nonce);
			// We can't have a leading 0 byte
			if (nonce [0] == 0) {
				nonce [0] = 1;
			}

			var parms = new ParametersWithIV(new KeyParameter(cloakKey), nonce);
			var chacha = new ChaChaEngine(20);
			chacha.Init(true, parms);
			chacha.ProcessBytes (FullPacket, 0, FullPacket.Length, outData, 8);
			Buffer.BlockCopy (nonce, 0, outData, 0, 8);

			return outData;
		}
	}
}