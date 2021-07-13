using System;
using System.Collections.Generic;
using System.Text;

namespace SMBLibrary.Client.Enums
{
    public enum PacketSendStatus
    {
        Unknown,
        Success,
        SocketException,
        ObjectDisposedException
    }
}
