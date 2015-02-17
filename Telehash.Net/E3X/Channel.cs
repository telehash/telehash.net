using System;

namespace Telehash.E3X
{
	public enum ChannelState
	{
		Opening,
		Open,
		Ended
	}

	public interface IChannel
	{
		uint ID { get; set; }

		ChannelState state { get; set; }
		Exchange ex { get; set; }

		Packet Send(Packet innerPacket);
	}

	/*
	public class ReliableChannel : IChannel
	{
		
	}

	public class UnreliableChannel : IChannel
	{
	}
	*/
}