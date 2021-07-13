using System;

namespace RedstoneSmb.SMB2.Enums.Read
{
    [Flags]
    public enum ReadFlags : byte
    {
        Unbuffered = 0x01 // SMB2_READFLAG_READ_UNBUFFERED;
    }
}