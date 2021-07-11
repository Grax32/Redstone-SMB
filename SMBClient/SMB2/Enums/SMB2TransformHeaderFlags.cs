using System;

namespace SMBLibrary.SMB2.Enums
{
    [Flags]
    public enum SMB2TransformHeaderFlags : ushort
    {
        Encrypted = 0x0001
    }
}