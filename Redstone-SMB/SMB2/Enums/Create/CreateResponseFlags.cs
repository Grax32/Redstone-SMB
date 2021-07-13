using System;

namespace RedstoneSmb.SMB2.Enums.Create
{
    [Flags]
    public enum CreateResponseFlags : byte
    {
        ReparsePoint = 0x01 // SMB2_CREATE_FLAG_REPARSEPOINT
    }
}