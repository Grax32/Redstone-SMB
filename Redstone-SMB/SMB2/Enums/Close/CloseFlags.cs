using System;

namespace RedstoneSmb.SMB2.Enums.Close
{
    [Flags]
    public enum CloseFlags : byte
    {
        PostQueryAttributes = 0x0001 // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    }
}