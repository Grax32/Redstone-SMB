/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using RedstoneSmb.Enums;
using RedstoneSmb.Models;
using RedstoneSmb.NTFileStore;
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
using RedstoneSmb.SMB2.Commands;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Create;
using RedstoneSmb.SMB2.Structures;

namespace RedstoneSmb.Client
{
    public class Smb2FileStore : ISmbFileStore
    {
        private const int BytesPerCredit = 65536;

        private readonly Smb2Client _mClient;
        private readonly bool _mEncryptShareData;
        private readonly uint _mTreeId;

        public Smb2FileStore(Smb2Client client, uint treeId, bool encryptShareData)
        {
            _mClient = client;
            _mTreeId = treeId;
            _mEncryptShareData = encryptShareData;
        }

        public NtStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess,
            FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition,
            CreateOptions createOptions, SecurityContext securityContext)
        {
            handle = null;
            fileStatus = FileStatus.FileDoesNotExist;
            var request = new CreateRequest
            {
                Name = path,
                DesiredAccess = desiredAccess,
                FileAttributes = fileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                ImpersonationLevel = ImpersonationLevel.Impersonation
            };
            TrySendCommand(request);

            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if (response.Header.Status == NtStatus.StatusSuccess && response is CreateResponse createResponse)
                {
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                }

                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus CloseFile(object handle)
        {
            var request = new CloseRequest {FileId = (FileId) handle};

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null) return response.Header.Status;

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus ReadFile(out byte[] data, object handle, long offset, int maxCount)
        {
            data = null;
            var request = new ReadRequest
            {
                FileId = (FileId) handle,
                Offset = (ulong) offset,
                ReadLength = (uint) maxCount
            };

            request.Header.CreditCharge = (ushort) Math.Ceiling((double) maxCount / BytesPerCredit);

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if (response.Header.Status == NtStatus.StatusSuccess && response is ReadResponse readResponse)
                    data = readResponse.Data;
                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data)
        {
            numberOfBytesWritten = 0;
            var request = new WriteRequest
            {
                FileId = (FileId) handle,
                Offset = (ulong) offset,
                Data = data
            };
            request.Header.CreditCharge = (ushort) Math.Ceiling((double) data.Length / BytesPerCredit);

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if (response.Header.Status == NtStatus.StatusSuccess && response is WriteResponse writeResponse)
                    numberOfBytesWritten = (int) writeResponse.Count;

                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName,
            FileInformationClass informationClass)
        {
            result = new List<QueryDirectoryFileInformation>();
            var request = new QueryDirectoryRequest();
            request.Header.CreditCharge = (ushort) Math.Ceiling((double) _mClient.MaxTransactSize / BytesPerCredit);
            request.FileInformationClass = informationClass;
            request.Reopen = true;
            request.FileId = (FileId) handle;
            request.OutputBufferLength = _mClient.MaxTransactSize;
            request.FileName = fileName;

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                while (response.Header.Status == NtStatus.StatusSuccess && response is QueryDirectoryResponse)
                {
                    var page = ((QueryDirectoryResponse) response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    TrySendCommand(request);
                    response = _mClient.WaitForCommand(request.MessageId);
                }

                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus GetFileInformation(out FileInformation result, object handle,
            FileInformationClass informationClass)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileId) handle;

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if (response.Header.Status == NtStatus.StatusSuccess && response is QueryInfoResponse)
                    result = ((QueryInfoResponse) response).GetFileInformation(informationClass);
                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus SetFileInformation(object handle, FileInformation information)
        {
            var request = new SetInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileId) handle;
            request.SetFileInformation(information);

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null) return response.Header.Status;

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus GetFileSystemInformation(out FileSystemInformation result,
            FileSystemInformationClass informationClass)
        {
            result = null;
            var status = CreateFile(out var fileHandle, out var fileStatus, string.Empty,
                (AccessMask) DirectoryAccessMask.FileListDirectory |
                (AccessMask) DirectoryAccessMask.FileReadAttributes | AccessMask.Synchronize, 0,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FileOpen,
                CreateOptions.FileSynchronousIoNonalert | CreateOptions.FileDirectoryFile, null);
            if (status != NtStatus.StatusSuccess) return status;

            status = GetFileSystemInformation(out result, fileHandle, informationClass);
            CloseFile(fileHandle);
            return status;
        }

        public NtStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public NtStatus GetSecurityInformation(out SecurityDescriptor result, object handle,
            SecurityInformation securityInformation)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileId) handle;

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if (response.Header.Status == NtStatus.StatusSuccess && response is QueryInfoResponse)
                    result = ((QueryInfoResponse) response).GetSecurityInformation();
                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus SetSecurityInformation(object handle, SecurityInformation securityInformation,
            SecurityDescriptor securityDescriptor)
        {
            return NtStatus.StatusNotSupported;
        }

        public NtStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter,
            bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NtStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public NtStatus DeviceIoControl(object handle, uint ctlCode, byte[] input, out byte[] output,
            int maxOutputLength)
        {
            output = null;
            var request = new IoCtlRequest();
            request.Header.CreditCharge = (ushort) Math.Ceiling((double) maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFsCtl = true;
            request.FileId = (FileId) handle;
            request.Input = input;
            request.MaxOutputResponse = (uint) maxOutputLength;
            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if ((response.Header.Status == NtStatus.StatusSuccess ||
                     response.Header.Status == NtStatus.StatusBufferOverflow) &&
                    response is IoCtlResponse) output = ((IoCtlResponse) response).Output;
                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        public NtStatus Disconnect()
        {
            var request = new TreeDisconnectRequest();
            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null) return response.Header.Status;

            return NtStatus.StatusInvalidSmb;
        }

        public uint MaxReadSize => _mClient.MaxReadSize;

        public uint MaxWriteSize => _mClient.MaxWriteSize;

        public NtStatus GetFileSystemInformation(out FileSystemInformation result, object handle,
            FileSystemInformationClass informationClass)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileId) handle;

            TrySendCommand(request);
            var response = _mClient.WaitForCommand(request.MessageId);
            if (response != null)
            {
                if (response.Header.Status == NtStatus.StatusSuccess && response is QueryInfoResponse)
                    result = ((QueryInfoResponse) response).GetFileSystemInformation(informationClass);
                return response.Header.Status;
            }

            return NtStatus.StatusInvalidSmb;
        }

        private void TrySendCommand(Smb2Command request)
        {
            request.Header.TreeId = _mTreeId;
            _mClient.TrySendCommand(request, _mEncryptShareData);
        }

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            switch (createAction)
            {
                case CreateAction.FileSuperseded:
                    return FileStatus.FileSuperseded;
                case CreateAction.FileOpened:
                    return FileStatus.FileOpened;
                case CreateAction.FileCreated:
                    return FileStatus.FileCreated;
                case CreateAction.FileOverwritten:
                    return FileStatus.FileOverwritten;
                default:
                    return FileStatus.FileOpened;
            }
        }
    }
}