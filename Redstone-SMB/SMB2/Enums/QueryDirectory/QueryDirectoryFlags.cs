using System;

namespace RedstoneSmb.SMB2.Enums.QueryDirectory
{
    [Flags]
    public enum QueryDirectoryFlags : byte
    {
        Smb2RestartScans = 0x01,
        Smb2ReturnSingleEntry = 0x02,
        Smb2IndexSpecified = 0x04,
        Smb2Reopen = 0x10
    }
}