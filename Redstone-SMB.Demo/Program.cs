using RedstoneSmb.Client;

namespace RedstoneSMB.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            var client = new Smb2Client();

            var fileStore = client.TreeConnect("", out var status);
        }
    }
}
