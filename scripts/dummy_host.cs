// dummy_host.cs
// Loads a stand-in DLL (a renamed copy of a harmless system DLL, e.g.
// version.dll -> liboradb.dll) so it can act as a target process for
// Rule 1 testing. Compile with:
//   csc.exe dummy_host.cs
using System;
using System.Runtime.InteropServices;
using System.Threading;

class DummyHost
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string dllToLoad);

    static void Main()
    {
        IntPtr handle = LoadLibrary(@"C:\Allians\liboradb.dll");
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("Failed to load DLL.");
            return;
        }
        Console.WriteLine("liboradb.dll loaded. PID: " + System.Diagnostics.Process.GetCurrentProcess().Id);
        Console.WriteLine("Sleeping for 5 minutes to stay alive for testing...");
        Thread.Sleep(300000);
    }
}
