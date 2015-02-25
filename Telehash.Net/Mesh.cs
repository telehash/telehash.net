using System;
using Newtonsoft.Json.Linq;
using System.IO;
using Telehash.E3X;
using System.Collections.Generic;
using System.Text;

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

		Dictionary<string, Link> Links;

		public Mesh ()
		{
			self = new Telehash.E3X.Self ();
			Links = new Dictionary<string, Link> ();
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
			var cs = new CipherSet1a ();
			cs.Generate ();
			Self.CipherSets.Add (cs.CSID, cs);
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

		public string Json(bool includePrivate = false)
		{
			JArray allKeys = new JArray ();
			foreach (var cs in self.CipherSets) {
				JObject csData = new JObject ();
				csData ["cs"] = cs.Value.CSID.ToString ("x2");
				csData ["public"] = Base32Encoder.Encode (cs.Value.Keys.PublicKey);
				if (includePrivate) {
					csData ["secret"] = Base32Encoder.Encode (cs.Value.Keys.PrivateKey);
				}
			}

			return allKeys.ToString ();
		}

		public Uri URI {
			get {
				StringBuilder outString = new StringBuilder ();
				outString.Append ("mesh://");
				outString.Append ("/?");
				foreach (var cs in self.CipherSets) {
					outString.Append (cs.Key.ToString("x2"));
					outString.Append ("=");
					outString.Append (Base32Encoder.EncodeStripped(cs.Value.Keys.PublicKey));
				}

				return new Uri(outString.ToString ());
			}
		}

		public string Hashname {
			get {
				Dictionary<string, string> csKeys = new Dictionary<string, string> (self.CipherSets.Count);
				foreach (var cs in self.CipherSets) {
					csKeys.Add (cs.Key.ToString("x2"), Base32Encoder.EncodeStripped (cs.Value.Keys.PublicKey));
				}
				return Telehash.Hashname.FromKeys (csKeys);
			}
		}

		public void Receive(Pipe pipe, Packet packet)
		{
			if (pipe == null || packet == null || packet.FullPacket.Length == 0) {
				DebugLog ("Invalid data sent to Receive");
				return;
			}

			DebugLog ("Received a packet: " + packet.ToDebugString());
			DebugLog ("Head length: " + packet.HeadLength + "\n");
			DebugLog ("First head byte: " + packet.HeadBytes [0] + "\n");

			// Process handshakes
			if (packet.HeadLength == 1) {
				DebugLog ("Processing a handshake");
				var inner = self.Decrypt (packet);
				if (inner == null) {
					DebugLog ("There was no inner packet\n");
					return;
				}
				DebugLog ("Decrypted");
				DebugLog (inner.ToDebugString());

				DebugLog ("HERE");

				JToken msgType;
				bool gotValue = inner.Head.TryGetValue("type", out msgType);

				// TODO:  Handle other types correctly
				if (gotValue && msgType.ToString() != "key") {
					DebugLog ("We can only handle key type messages right now\n");
					return;
				}

				DebugLog ("Building hashname");
				// Get the hashname
				var hashKeys = new Dictionary<string, string> ();
				foreach (var entry in inner.Head) {
					// Skip the other head entries
					if (entry.Key == "at" || entry.Key == "type") {
						continue;
					}
					if (entry.Key.Length > 2) {
						continue;
					}

					// TODO:  Move to the new inner packet syntax
					hashKeys.Add (entry.Key, entry.Value.ToString());
				}

				var fromHashname = Telehash.Hashname.FromKey ("1a", inner.Body, hashKeys);
				DebugLog ("Incoming hashname: " + fromHashname);

				// TODO:  Method to approve or reject the hashname?

				Link newLink = new Link (fromHashname);
				newLink.Exchange = new Exchange (self, 0x1a, inner.Body);
				newLink.Exchange.OutAt = packet.Head ["at"];
				newLink.Pipes.Add (pipe);
				Links.Add (newLink);
			}

			DebugLog ("We're out\n");
		}

		public void DebugLog(string message)
		{
			DebugLogEvent (message);
		}
	}
}

