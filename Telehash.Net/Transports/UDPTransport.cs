﻿using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Collections.Generic;
using Telehash.E3X;

namespace Telehash
{
	public class UDPPipe : Pipe
	{
		public IPEndPoint remoteEndpoint { get; set; }
	}

	public class UDPTransport : ITransport
	{
		UdpClient client;
		List<UDPPipe> pipes;
		bool KeepListening;

		public UDPTransport (IPEndPoint localEndpoint)
		{
			client = new UdpClient (localEndpoint);
			pipes = new List<UDPPipe> ();
			KeepListening = false;
		}
			
		public void Listen(Mesh mesh)
		{
			KeepListening = true;
			Task.Run (async () => {
				while (KeepListening) {
					var received = await client.ReceiveAsync();
					mesh.DebugLog("We got some data: " + Encoding.UTF8.GetString(received.Buffer) + "\n");

					var pipe = GetPipe(received.RemoteEndPoint);
					mesh.DebugLog("Pipe is " + pipe.ToString() + "\n");
					if (pipe == null) {
						mesh.DebugLog("No pipe, we're bailing");
						continue;
					}
					var packet = new Packet(received.Buffer);
					mesh.DebugLog("Packet is here");
					if (packet == null || packet.FullPacket == null) {
						mesh.DebugLog("No packet bailing");
						continue;
					}

					mesh.Receive(pipe, packet);
				}
			});
		}

		UDPPipe GetPipe(IPEndPoint remoteEndpoint)
		{
			foreach (var pipe in pipes) {
				if (pipe.remoteEndpoint == remoteEndpoint) {
					return pipe;
				}
			}

			var newPipe = new UDPPipe ();
			newPipe.remoteEndpoint = remoteEndpoint;
			pipes.Add (newPipe);

			return newPipe;
		}
	}
}
