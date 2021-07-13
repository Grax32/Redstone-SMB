namespace RedstoneSmb.SMB2.Enums.Create
{
    public enum CreateAction : uint
    {
        FileSuperseded = 0x00000000,
        FileOpened = 0x00000001,
        FileCreated = 0x00000002,
        FileOverwritten = 0x00000003
    }
}