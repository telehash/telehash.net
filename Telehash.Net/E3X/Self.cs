using System;
using System.Collections.Generic;

namespace Telehash.E3X
{
	public class Self
	{
		public IDictionary<byte, ICipherSet> CipherSets;

		public Self ()
		{
			CipherSets = new Dictionary<byte, ICipherSet> ();
		}

		/// <summary>
		/// Attempt to Decrypt a packet sent to us.
		/// </summary>
		/// <param name="outer">A packet to attempt to decrypt</param>
		public Packet Decrypt(Packet outer) 
		{
			return null;
		}
	}
}

