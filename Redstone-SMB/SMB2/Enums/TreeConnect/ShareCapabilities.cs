using System;

namespace RedstoneSmb.SMB2.Enums.TreeConnect
{
    [Flags]
    public enum ShareCapabilities : uint
    {
        Dfs = 0x00000008, // SMB2_SHARE_CAP_DFS
        ContinuousAvailability = 0x00000010, // SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
        Scaleout = 0x00000020, // SMB2_SHARE_CAP_SCALEOUT
        Cluster = 0x00000040, // SMB2_SHARE_CAP_CLUSTER
        Asymmetric = 0x00000080 // SMB2_SHARE_CAP_ASYMMETRIC
    }
}