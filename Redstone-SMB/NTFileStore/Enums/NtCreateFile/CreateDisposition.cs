namespace RedstoneSmb.NTFileStore.Enums.NtCreateFile
{
    public enum CreateDisposition : uint
    {
        /// <summary>
        ///     If the file already exists, replace it with the given file.
        ///     If it does not, create the given file.
        /// </summary>
        FileSupersede = 0x0000,

        /// <summary>
        ///     If the file already exists, open it [instead of creating a new file].
        ///     If it does not, fail the request [and do not create a new file].
        /// </summary>
        FileOpen = 0x0001,

        /// <summary>
        ///     If the file already exists, fail the request [and do not create or open the given file].
        ///     If it does not, create the given file.
        /// </summary>
        FileCreate = 0x0002,

        /// <summary>
        ///     If the file already exists, open it.
        ///     If it does not, create the given file.
        /// </summary>
        FileOpenIf = 0x0003,

        /// <summary>
        ///     If the file already exists, open it and overwrite it.
        ///     If it does not, fail the request.
        /// </summary>
        FileOverwrite = 0x0004,

        /// <summary>
        ///     If the file already exists, open it and overwrite it.
        ///     If it does not, create the given file.
        /// </summary>
        FileOverwriteIf = 0x0005
    }
}