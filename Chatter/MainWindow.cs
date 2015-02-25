using System;
using Gtk;
using Telehash;

public partial class MainWindow: Gtk.Window
{
	Mesh mesh;
	UDPTransport udp;

	public MainWindow () : base (Gtk.WindowType.Toplevel)
	{
		Build ();
		mesh = new Mesh ();
		mesh.Generate ();

		textview2.Buffer.Text += "Hashname: " + mesh.Hashname + "\n";

		var builder = new UriBuilder (mesh.URI);
		builder.Host = "127.0.0.1";
		builder.Port = 8989;
		textview2.Buffer.Text += builder.ToString () + "\n";

		udp = new UDPTransport (new System.Net.IPEndPoint (System.Net.IPAddress.Any, 8989));
		udp.Listen (mesh);
		mesh.DebugLogEvent += new DebugLogHandler (OnDebugLog);
	}

	protected void OnDeleteEvent (object sender, DeleteEventArgs a)
	{
		Application.Quit ();
		a.RetVal = true;
	}

	void OnDebugLog(string message)
	{
		textview2.Buffer.Text += message + "\n";
	}
}
