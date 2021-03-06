﻿using System;
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
		Packet MessageDecrypt (Packet outer);
		bool MessageVerify (ICipherSetRemoteInfo remoteInfo, Packet outer);
		Packet ChannelEncrypt(ICipherSetRemoteInfo info, Packet inner);
		Packet ChannelDecrypt(ICipherSetRemoteInfo info, Packet outer);
		void Prepare(ICipherSetRemoteInfo info, Packet outer);
	}

	public interface ICipherSetRemoteInfo
	{
		byte[] Token { get; set; }
	}
}

