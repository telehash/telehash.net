using System;
using System.Collections;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace Telehash.E3X
{
	public class Exchange
	{
		public Self Local;
		public byte[] Token;


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
			return false;
		}

		public void Encrypt(Packet msg)
		{
		}

		public void Sync(Packet handshake)
		{
		}

		public void Receive(IChannel channel)
		{
		}

		/// <summary>
		/// Generate a handshake packet for the current keys
		/// </summary>
		public Packet Handshake(byte csid)
		{
			Packet inner = new Packet ();
			foreach (var csItem in Local.CipherSets) {
				if (csItem.Value.CSID == csid) {
					inner.Head[csid.ToString()] = true;
					inner.Body = csItem.Value.Keys.PublicKey;
				} else {
					inner.Head.Add (csItem.Value.CSID.ToString (), Base32Encoder.Encode (csItem.Value.Keys.PublicKey));
				}
			}
			inner.Head.Add ("at", currentAt++);

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