using System;
using System.Linq;
using System.Collections.Generic;
using Telehash.E3X;

namespace Telehash
{
	public class Link
	{
		public Mesh Mesh { get; set; }
		public string Hashname { get; set; }
		public E3X.Exchange Exchange { get; set; }
		public byte CSID { get; set; }
		public string Token { get; set; }
		public List<Pipe> Pipes { get; set; }

		private void sharedSetup(string hashname)
		{
			Pipes = new List<Pipe> ();
			this.Hashname = hashname;
		}

		public Link (string hashname)
		{
			sharedSetup (hashname);
		}

		public Link (Mesh mesh, string hashname, byte[] remotePublicKey)
		{
			sharedSetup (hashname);
			Mesh = mesh;
			Exchange = new Exchange (Mesh.Self, 0x1a, remotePublicKey);
		}

		public bool Handshake(Packet outer)
		{
			var linkData = Packet.DecodePacket (outer.Body);
			if (Exchange == null) {
				Exchange = new Exchange (Mesh.Self, 0x1a, linkData.Body);
				Exchange.OutAt = (uint)outer.Head ["at"];

				var tokenData = outer.Parent.Body.Take (16).ToArray ();
				var tokenHash = Helpers.SHA256Hash (tokenData).Take (16).ToArray ();
				Token = Helpers.ToHexSring (tokenHash);
			}
			if (!Exchange.Verify (outer.Parent)) {
				return false;
			}
			Exchange.Sync (outer);

			return true;
		}

		public void AddPipe(Pipe pipe)
		{
			Pipes.Add (pipe);
			pipe.Send (Exchange.Handshake (0x1a));
		}

		public void Receive(Packet packet, Pipe pipe)
		{

		}
	}
}

