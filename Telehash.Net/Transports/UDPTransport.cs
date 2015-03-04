using System;
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
		public ITransport Transport { get; set; }
		public UdpClient Client { get; set; }
		public IPEndPoint remoteEndpoint { get; set; }
		public void Send (Packet packet)
		{
			packet.Encode ();
			Client.Send (packet.FullPacket, packet.FullPacket.Length, remoteEndpoint);
		}
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
					mesh.DebugLog("We got some data: " + Helpers.ToHex(received.Buffer) + "\n");

					var pipe = GetPipe(received.RemoteEndPoint);
					mesh.DebugLog("Pipe is " + pipe.ToString() + "\n");
					if (pipe == null) {
						mesh.DebugLog("No pipe, we're bailing");
						continue;
					}
					var packet = Packet.Decloak(received.Buffer);
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
			newPipe.Transport = this;
			newPipe.Client = client;
			newPipe.remoteEndpoint = remoteEndpoint;
			pipes.Add (newPipe);

			return newPipe;
		}
	}
}

