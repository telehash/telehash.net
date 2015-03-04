using System;
using Telehash.E3X;

namespace Telehash
{
	public interface Pipe
	{
		ITransport Transport { get; set; }

		void Send(Packet packet);
	}
}

