using System;

namespace Telehash.E3X
{
	public interface IKeyPair
	{
		byte[] PublicKey { get; }
		byte[] PrivateKey { get; }
	}
}

