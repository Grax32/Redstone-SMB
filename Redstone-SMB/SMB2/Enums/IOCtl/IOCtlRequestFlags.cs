using System;

namespace RedstoneSmb.SMB2.Enums.IOCtl
{
    [Flags]
    public enum IoCtlRequestFlags : uint
    {
        IsFsCtl = 0x00000001 // SMB2_0_IOCTL_IS_FSCTL
    }
}