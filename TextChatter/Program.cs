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
			AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);

			var c = new Chatter ();
			c.Start ();

			string line;
			while ((line = Console.ReadLine ()) != "exit") {
				Console.Write ("> ");
			}
		}

		static void Application_ThreadException(object sender, ThreadExceptionEventArgs e)
		{
			Console.WriteLine("Unhandled Thread Exception: {0}", e.Exception.Message);
			// here you can log the exception ...
		}

		static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
		{
			Console.WriteLine("Unhandled Exception: {0}", (e.ExceptionObject as Exception).Message);
			// here you can log the exception ...
		}


	}

	class Chatter
	{
		Mesh mesh;
		UDPTransport udp;

		public void Start()
		{
			mesh = new Mesh ();
			mesh.Generate ();

			Console.WriteLine ("Hashname: " + mesh.Hashname);

			var builder = new UriBuilder (mesh.URI);
			builder.Host = "127.0.0.1";
			builder.Port = 8989;
			Console.WriteLine (builder.ToString ());

			udp = new UDPTransport (new System.Net.IPEndPoint (System.Net.IPAddress.Any, 8989));
			udp.Listen (mesh);
			mesh.DebugLogEvent += new DebugLogHandler (OnDebugLog);
		}

		void OnDebugLog(string message)
		{
			Console.WriteLine (message);
		}
	}
}
