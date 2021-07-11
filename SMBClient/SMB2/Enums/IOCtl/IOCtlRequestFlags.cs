using System;

namespace SMBLibrary.SMB2.Enums.IOCtl
{
    [Flags]
    public enum IOCtlRequestFlags : uint
    {
        IsFSCtl = 0x00000001 // SMB2_0_IOCTL_IS_FSCTL
    }
}