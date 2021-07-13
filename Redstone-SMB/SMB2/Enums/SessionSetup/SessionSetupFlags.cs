using System;

namespace RedstoneSmb.SMB2.Enums.SessionSetup
{
    [Flags]
    public enum SessionSetupFlags : byte
    {
        Binding = 0x01 // SMB2_SESSION_FLAG_BINDING
    }
}