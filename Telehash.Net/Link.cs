using System;
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
			Exchange = new Exchange (Mesh.Self, 0x1a, outer.Body);
			Exchange.OutAt = (uint)outer.Head ["at"];
			if (!Exchange.Verify (outer)) {
				return false;
			}
			Exchange.Sync (outer);

			return true;
		}

		public void AddPipe(Pipe pipe)
		{
			Pipes.Add (pipe);
			pipe.Send (Exchange.Handshake (0x1a, true));
		}

		public void Receive(Packet packet, Pipe pipe)
		{

		}
	}
}

