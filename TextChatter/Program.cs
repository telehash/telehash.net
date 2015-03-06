using System;
using Telehash;
using Telehash.E3X;
using System.Threading;

namespace TextChatter
{
	class MainClass
	{


		public static void Main (string[] args)
		{
			//Application.ThreadException += new ThreadExceptionEventHandler(Application_ThreadException);
			AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

			var c = new Chatter ();
			c.Start ();

			string line;
			while ((line = Console.ReadLine ()) != "exit") {
				var cmdargs = line.Split(' ');
				if (cmdargs [0] == "link") {
					Console.WriteLine ("Connecting to {0}", cmdargs [1]);
					c.Link (cmdargs [1]);
				}
				Console.Write ("> ");
			}
		}

		static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
		{
			Console.WriteLine("Unhandled Exception: {0}", (e.ExceptionObject as Exception).Message);
			// here you can log the exception ...
		}


	}

	class Chatter
	{
		public Mesh Mesh { get; set; }
		UDPTransport udp;

		public void Start()
		{
			Mesh = new Mesh ();
			Mesh.Generate ();

			Console.WriteLine ("Hashname: " + Mesh.Hashname);

			var builder = new UriBuilder (Mesh.URI);
			builder.Host = "127.0.0.1";
			builder.Port = 8989;
			Console.WriteLine (builder.ToString ());

			udp = new UDPTransport (new System.Net.IPEndPoint (System.Net.IPAddress.Any, 8989));
			udp.Listen (Mesh);
			Mesh.DebugLogEvent += new DebugLogHandler (OnDebugLog);
		}

		public void Link(string uri)
		{
			try {
			var realUri = new Uri (uri);
			var link = Mesh.Add (realUri);
			link.AddPipe (udp.PipeTo (new System.Net.IPEndPoint (System.Net.IPAddress.Parse(realUri.Host), realUri.Port)));
			} catch (Exception ex) {
				Console.WriteLine ("Error: {0}", ex.Message);
				Console.WriteLine ("Stack: {0}", ex.StackTrace);
			}
		}

		void OnDebugLog(string message)
		{
			Console.WriteLine (message);
		}
	}
}
