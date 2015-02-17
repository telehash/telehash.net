using System;
using Newtonsoft.Json.Linq;

namespace Telehash.E3X
{
	public interface ICipherSet
	{
		byte CSID { get; }
		IKeyPair Keys { get; }
		void Generate();
		void GenerateEphemeralKeys (ICipherSetRemoteInfo remoteInfo);
		void LoadKeys(byte[] publicKeyData, byte[] privateKeyData);
		Packet MessageEncrypt (ICipherSetRemoteInfo remoteInfo, Packet inner);
		Packet MessageDecrypt (ICipherSetRemoteInfo remoteInfo, Packet outer);
		Packet ChannelEncrypt(ICipherSetChannelInfo info, Packet inner);
		Packet ChannelDecrypt(ICipherSetChannelInfo info, Packet outer);
	}

	public interface ICipherSetChannelInfo
	{
	}

	public interface ICipherSetRemoteInfo
	{
	}
}

