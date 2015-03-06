using System;
using System.Collections;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace Telehash.E3X
{
	public class Exchange
	{
		public Self Local { get; set; }
		public byte[] Token { get; set; }
		public uint OutAt { get; set; }

		uint currentAt;
		ICipherSetRemoteInfo remoteInfo;
		ICipherSet cipherSet;

		public Exchange (Self localIdentity, byte csid, byte[] publicKey)
		{
			Token = new byte[16];
			currentAt = 1;

			Local = localIdentity;

			cipherSet = localIdentity.CipherSets [csid];
			var ri = new CS1ARemoteInfo ();
			ri.RemotePublicKey = publicKey;
			cipherSet.GenerateEphemeralKeys (ri);
			remoteInfo = ri;
		}

		public bool Verify(Packet msg)
		{
			return cipherSet.MessageVerify (remoteInfo, msg);
		}

		public void Encrypt(Packet msg)
		{
		}

		public void Sync(Packet handshake)
		{
			cipherSet.Prepare (remoteInfo, handshake);
		}

		public Packet Receive(Packet packet)
		{
			return cipherSet.ChannelDecrypt(remoteInfo, packet);
		}

		/// <summary>
		/// Generate a handshake packet for the current keys
		/// </summary>
		public Packet Handshake(byte csid, bool isReply = false)
		{
			Packet inner = new Packet ();
			Packet keyPacket = new Packet ();
			foreach (var csItem in Local.CipherSets) {
				if (csItem.Value.CSID == csid) {
					keyPacket.Body = csItem.Value.Keys.PublicKey;
				} else {
					keyPacket.Head.Add (csItem.Value.CSID.ToString (), Base32Encoder.Encode (csItem.Value.Keys.PublicKey));
				}
			}
			if (isReply) {
				inner.Head.Add ("at", OutAt);
			} else {
				inner.Head.Add ("at", currentAt++);
			}
			keyPacket.Encode ();
			inner.Body = keyPacket.FullPacket;
			inner.Encode ();

			Packet outer = Local.CipherSets[csid].MessageEncrypt(remoteInfo, inner);
			outer.HeadBytes = new byte[1];
			outer.HeadLength = 1;
			outer.HeadBytes [0] = csid;
			outer.Encode ();

			return outer;
		}
	}
}