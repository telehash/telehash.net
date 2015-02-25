using System;
using System.Collections.Generic;

namespace Telehash
{
	public class Link
	{
		public string Hashname { get; set; }
		public E3X.Exchange Exchange { get; set; }
		public byte CSID { get; set; }
		public string Token { get; set; }
		public List<Pipe> Pipes { get; set; }

		public Link (string Hashname)
		{
			Pipes = new List<Pipe> ();
			Hashname = Hashname;
		}
	}
}

