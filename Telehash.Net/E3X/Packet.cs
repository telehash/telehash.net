using System;
using System.Net;
using System.Linq;
using System.IO;
using System.Text;
using Newtonsoft.Json.Linq;

namespace Telehash.E3X
{
	public class Packet
	{
		public ushort HeadLength;
		public byte[] FullPacket;
		public JObject Head;
		public byte[] HeadBytes;
		public ushort BodyLength;
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

		/// <summary>
		/// Decode the packet data into the fields of the class.
		/// </summary>
		/// <param name="packetData">Packet data.</param>
		void Decode(byte[] packetData)
		{
			// Gotta have a length!
			if (packetData.Length < 2) {
				return;
			}

			short tmp = BitConverter.ToInt16 (packetData, 0);
			HeadLength = (ushort)IPAddress.NetworkToHostOrder(tmp);
			BodyLength = (ushort)(packetData.Length - HeadLength - 2);

			if (HeadLength > packetData.Length || (HeadLength + BodyLength > packetData.Length)) {
				return;
			}

			FullPacket = packetData;

			if (HeadLength >= 7) {
				string jsonData = System.Text.Encoding.UTF8.GetString(packetData.Skip (2).Take (HeadLength).ToArray());
				Head = JObject.Parse (jsonData);
			}
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
	}
}