/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using RedstoneSmb.Enums;
using RedstoneSmb.Models;
using RedstoneSmb.NTFileStore.Enums.AccessMask;
using RedstoneSmb.NTFileStore.Enums.FileInformation;
using RedstoneSmb.NTFileStore.Enums.NtCreateFile;
using RedstoneSmb.NTFileStore.Structures.FileInformation;
using RedstoneSmb.NTFileStore.Structures.FileInformation.Query;

namespace RedstoneSmb.NTFileStore
{
    public class NtFileStoreHelper
    {
        public static FileAccess ToCreateFileAccess(AccessMask desiredAccess, CreateDisposition createDisposition)
        {
            FileAccess result = 0;

            if (((FileAccessMask) desiredAccess & FileAccessMask.FileReadData) > 0 ||
                ((FileAccessMask) desiredAccess & FileAccessMask.FileReadEa) > 0 ||
                ((FileAccessMask) desiredAccess & FileAccessMask.FileReadAttributes) > 0 ||
                (desiredAccess & AccessMask.MaximumAllowed) > 0 ||
                (desiredAccess & AccessMask.GenericAll) > 0 ||
                (desiredAccess & AccessMask.GenericRead) > 0)
                result |= FileAccess.Read;

            if (((FileAccessMask) desiredAccess & FileAccessMask.FileWriteData) > 0 ||
                ((FileAccessMask) desiredAccess & FileAccessMask.FileAppendData) > 0 ||
                ((FileAccessMask) desiredAccess & FileAccessMask.FileWriteEa) > 0 ||
                ((FileAccessMask) desiredAccess & FileAccessMask.FileWriteAttributes) > 0 ||
                (desiredAccess & AccessMask.Delete) > 0 ||
                (desiredAccess & AccessMask.WriteDac) > 0 ||
                (desiredAccess & AccessMask.WriteOwner) > 0 ||
                (desiredAccess & AccessMask.MaximumAllowed) > 0 ||
                (desiredAccess & AccessMask.GenericAll) > 0 ||
                (desiredAccess & AccessMask.GenericWrite) > 0)
                result |= FileAccess.Write;

            if (((DirectoryAccessMask) desiredAccess & DirectoryAccessMask.FileDeleteChild) > 0)
                result |= FileAccess.Write;

            // Technically, FILE_OPEN_IF should only require Write access if the file does not exist,
            // However, It's uncommon for a client to open a file with FILE_OPEN_IF
            // without requesting any kind of write access in the access mask.
            // (because [if the file does not exist] an empty file will be created without the ability to write data to the file). 
            if (createDisposition == CreateDisposition.FileCreate ||
                createDisposition == CreateDisposition.FileSupersede ||
                createDisposition == CreateDisposition.FileOpenIf ||
                createDisposition == CreateDisposition.FileOverwrite ||
                createDisposition == CreateDisposition.FileOverwriteIf)
                result |= FileAccess.Write;

            return result;
        }

        /// <summary>
        ///     Will return desired FileAccess rights to the file data.
        /// </summary>
        public static FileAccess ToFileAccess(AccessMask desiredAccess)
        {
            return ToFileAccess((FileAccessMask) desiredAccess);
        }

        /// <summary>
        ///     Will return desired FileAccess rights to the file data.
        /// </summary>
        public static FileAccess ToFileAccess(FileAccessMask desiredAccess)
        {
            FileAccess result = 0;
            if ((desiredAccess & FileAccessMask.FileReadData) > 0 ||
                (desiredAccess & FileAccessMask.MaximumAllowed) > 0 ||
                (desiredAccess & FileAccessMask.GenericAll) > 0 ||
                (desiredAccess & FileAccessMask.GenericRead) > 0)
                result |= FileAccess.Read;

            if ((desiredAccess & FileAccessMask.FileWriteData) > 0 ||
                (desiredAccess & FileAccessMask.FileAppendData) > 0 ||
                (desiredAccess & FileAccessMask.MaximumAllowed) > 0 ||
                (desiredAccess & FileAccessMask.GenericAll) > 0 ||
                (desiredAccess & FileAccessMask.GenericWrite) > 0)
                result |= FileAccess.Write;

            return result;
        }

        public static FileShare ToFileShare(ShareAccess shareAccess)
        {
            var result = FileShare.None;
            if ((shareAccess & ShareAccess.Read) > 0) result |= FileShare.Read;

            if ((shareAccess & ShareAccess.Write) > 0) result |= FileShare.Write;

            if ((shareAccess & ShareAccess.Delete) > 0) result |= FileShare.Delete;

            return result;
        }

        public static FileNetworkOpenInformation GetNetworkOpenInformation(INtFileStore fileStore, string path,
            SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            var openStatus = fileStore.CreateFile(out handle, out fileStatus, path,
                (AccessMask) FileAccessMask.FileReadAttributes, 0, ShareAccess.Read | ShareAccess.Write,
                CreateDisposition.FileOpen, 0, securityContext);
            if (openStatus != NtStatus.StatusSuccess) return null;
            FileInformation fileInfo;
            var queryStatus =
                fileStore.GetFileInformation(out fileInfo, handle, FileInformationClass.FileNetworkOpenInformation);
            fileStore.CloseFile(handle);
            if (queryStatus != NtStatus.StatusSuccess) return null;
            return (FileNetworkOpenInformation) fileInfo;
        }

        public static FileNetworkOpenInformation GetNetworkOpenInformation(INtFileStore fileStore, object handle)
        {
            FileInformation fileInfo;
            var status =
                fileStore.GetFileInformation(out fileInfo, handle, FileInformationClass.FileNetworkOpenInformation);
            if (status != NtStatus.StatusSuccess) return null;

            return (FileNetworkOpenInformation) fileInfo;
        }
    }
}