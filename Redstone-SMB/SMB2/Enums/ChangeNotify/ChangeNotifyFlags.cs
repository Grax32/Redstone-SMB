using System;

namespace RedstoneSmb.SMB2.Enums.ChangeNotify
{
    [Flags]
    public enum ChangeNotifyFlags : ushort
    {
        WatchTree = 0x0001 // SMB2_WATCH_TREE
    }
}