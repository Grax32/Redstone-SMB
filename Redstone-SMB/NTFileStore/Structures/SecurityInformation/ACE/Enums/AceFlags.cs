using System;

namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation.ACE.Enums
{
    [Flags]
    public enum AceFlags : byte
    {
        ObjectInheritAce = 0x01,
        ContainerInheritAce = 0x02,
        NoPropagateInheritAce = 0x04,
        InheritOnlyAce = 0x08,
        InheritedAce = 0x10,
        SuccessfulAccessAceFlag = 0x40,
        FailedAccessAceFlag = 0x80
    }
}