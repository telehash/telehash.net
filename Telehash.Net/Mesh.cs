using System;
using Newtonsoft.Json.Linq;
using System.IO;
using Telehash.E3X;

namespace Telehash
{
	public class JsonIdentity
	{

	}

	public delegate void DebugLogHandler(string message);

	public class Mesh
	{
		public event DebugLogHandler DebugLogEvent;
		Self self;
		public E3X.Self Self { 
			get {
				return self;
			}
		}

		public Mesh ()
		{
			self = new Telehash.E3X.Self ();
		}

		/// <summary>
		/// Load the keys and secrets.
		/// </summary>
		public void Load(string jsonIdentityFilePath)
		{
			JArray keys = (JArray)JToken.Parse (File.ReadAllText (jsonIdentityFilePath));

			foreach (var idEntry in keys) {
				if (idEntry ["cs"].Value<string>() == "1a") {
					// Create a 1a
					string keyData = idEntry ["secret"].Value<string>();
					if (keyData.Length == 0) {
						continue;
					}
					byte[] privKey = Base32Encoder.Decode (keyData);
					keyData = idEntry ["public"].Value<string>();
					if (keyData.Length == 0) {
						continue;
					}
					byte[] publicKey = Base32Encoder.Decode (keyData);

					CipherSet1a cs1a = new CipherSet1a ();
					cs1a.LoadKeys (publicKey, privKey);
					Self.CipherSets.Add (0x1a, cs1a);
				}
			}
		}

		/// <summary>
		/// Generate new keys for this Mesh instance.  The hashname of this Mesh will change.
		/// </summary>
		public void Generate()
		{
		}

		/// <summary>
		/// Create a new Link from the given url
		/// </summary>
		public Link Add(string addUrl)
		{
			return null;
		}

		/// <summary>
		/// Create a new Link from the given identity object
		/// </summary>
		/// <param name="remoteIdentity">Remote identity.</param>
		public Link Add(JObject remoteIdentity)
		{
			return null;
		}

		public void Receive(Pipe pipe, Packet packet)
		{
			DebugLog ("Received a packet");
			// Process handshakes
			if (packet.HeadLength == 1) {
				var inner = self.Decrypt (packet);
				Console.WriteLine (inner);
				DebugLog (inner.ToString());
			}
		}

		public void DebugLog(string message)
		{
			DebugLogEvent (message);
		}
	}
}

