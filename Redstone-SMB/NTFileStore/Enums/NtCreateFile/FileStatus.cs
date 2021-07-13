namespace RedstoneSmb.NTFileStore.Enums.NtCreateFile
{
    public enum FileStatus : uint
    {
        FileSuperseded = 0x00000000,
        FileOpened = 0x00000001,
        FileCreated = 0x00000002,
        FileOverwritten = 0x00000003,
        FileExists = 0x00000004,
        FileDoesNotExist = 0x00000005
    }
}