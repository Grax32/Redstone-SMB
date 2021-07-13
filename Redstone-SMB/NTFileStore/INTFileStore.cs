/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using RedstoneSmb.Enums;
using RedstoneSmb.Models;
using RedstoneSmb.NTFileStore.Enums;
using RedstoneSmb.NTFileStore.Enums.AccessMask;
using RedstoneSmb.NTFileStore.Enums.FileInformation;
using RedstoneSmb.NTFileStore.Enums.FileSystemInformation;
using RedstoneSmb.NTFileStore.Enums.NtCreateFile;
using RedstoneSmb.NTFileStore.Enums.SecurityInformation;
using RedstoneSmb.NTFileStore.Structures.FileInformation;
using RedstoneSmb.NTFileStore.Structures.FileInformation.QueryDirectory;
using RedstoneSmb.NTFileStore.Structures.FileSystemInformation;
using RedstoneSmb.NTFileStore.Structures.SecurityInformation;

namespace RedstoneSmb.NTFileStore
{
    public delegate void OnNotifyChangeCompleted(NtStatus status, byte[] buffer, object context);

    /// <summary>
    ///     A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner
    ///     dictated by the SMB protocol.
    /// </summary>
    public interface INtFileStore
    {
        NtStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess,
            FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition,
            CreateOptions createOptions, SecurityContext securityContext);

        NtStatus CloseFile(object handle);

        NtStatus ReadFile(out byte[] data, object handle, long offset, int maxCount);

        NtStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data);

        NtStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName,
            FileInformationClass informationClass);

        NtStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass);

        NtStatus SetFileInformation(object handle, FileInformation information);

        NtStatus GetFileSystemInformation(out FileSystemInformation result,
            FileSystemInformationClass informationClass);

        NtStatus SetFileSystemInformation(FileSystemInformation information);

        NtStatus GetSecurityInformation(out SecurityDescriptor result, object handle,
            SecurityInformation securityInformation);

        NtStatus SetSecurityInformation(object handle, SecurityInformation securityInformation,
            SecurityDescriptor securityDescriptor);

        /// <summary>
        ///     Monitor the contents of a directory (and its subdirectories) by using change notifications.
        ///     When something changes within the directory being watched this operation is completed.
        /// </summary>
        /// <returns>
        ///     STATUS_PENDING - The directory is being watched, change notification will be provided using callback method.
        ///     STATUS_NOT_SUPPORTED - The underlying object store does not support change notifications.
        ///     STATUS_INVALID_HANDLE - The handle supplied is invalid.
        /// </returns>
        NtStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree,
            int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context);

        NtStatus Cancel(object ioRequest);

        NtStatus DeviceIoControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength);
    }
}