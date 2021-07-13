/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using SMBLibrary.Enums;
using SMBLibrary.Models;
using SMBLibrary.NTFileStore;
using SMBLibrary.NTFileStore.Enums;
using SMBLibrary.NTFileStore.Enums.AccessMask;
using SMBLibrary.NTFileStore.Enums.FileInformation;
using SMBLibrary.NTFileStore.Enums.FileSystemInformation;
using SMBLibrary.NTFileStore.Enums.NtCreateFile;
using SMBLibrary.NTFileStore.Enums.SecurityInformation;
using SMBLibrary.NTFileStore.Structures.FileInformation;
using SMBLibrary.NTFileStore.Structures.FileInformation.QueryDirectory;
using SMBLibrary.NTFileStore.Structures.FileSystemInformation;
using SMBLibrary.NTFileStore.Structures.SecurityInformation;
using SMBLibrary.SMB2.Commands;
using SMBLibrary.SMB2.Enums;
using SMBLibrary.SMB2.Enums.Create;
using SMBLibrary.SMB2.Structures;

namespace SMBLibrary.Client
{
    public class SMB2FileStore : ISMBFileStore
    {
        private const int BytesPerCredit = 65536;

        private readonly SMB2Client m_client;
        private readonly bool m_encryptShareData;
        private readonly uint m_treeID;

        public SMB2FileStore(SMB2Client client, uint treeID, bool encryptShareData)
        {
            m_client = client;
            m_treeID = treeID;
            m_encryptShareData = encryptShareData;
        }

        public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess,
            FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition,
            CreateOptions createOptions, SecurityContext securityContext)
        {
            handle = null;
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
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

            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is CreateResponse createResponse)
                {
                    handle = createResponse.FileId;
                    fileStatus = ToFileStatus(createResponse.CreateAction);
                }

                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus CloseFile(object handle)
        {
            var request = new CloseRequest {FileId = (FileID) handle};

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null) return response.Header.Status;

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount)
        {
            data = null;
            var request = new ReadRequest
            {
                FileId = (FileID) handle,
                Offset = (ulong) offset,
                ReadLength = (uint) maxCount
            };

            request.Header.CreditCharge = (ushort) Math.Ceiling((double) maxCount / BytesPerCredit);

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is ReadResponse readResponse)
                    data = readResponse.Data;
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data)
        {
            numberOfBytesWritten = 0;
            var request = new WriteRequest
            {
                FileId = (FileID) handle,
                Offset = (ulong) offset,
                Data = data
            };
            request.Header.CreditCharge = (ushort) Math.Ceiling((double) data.Length / BytesPerCredit);

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is WriteResponse writeResponse)
                    numberOfBytesWritten = (int) writeResponse.Count;

                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName,
            FileInformationClass informationClass)
        {
            result = new List<QueryDirectoryFileInformation>();
            var request = new QueryDirectoryRequest();
            request.Header.CreditCharge = (ushort) Math.Ceiling((double) m_client.MaxTransactSize / BytesPerCredit);
            request.FileInformationClass = informationClass;
            request.Reopen = true;
            request.FileId = (FileID) handle;
            request.OutputBufferLength = m_client.MaxTransactSize;
            request.FileName = fileName;

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                while (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse)
                {
                    var page = ((QueryDirectoryResponse) response).GetFileInformationList(informationClass);
                    result.AddRange(page);
                    request.Reopen = false;
                    TrySendCommand(request);
                    response = m_client.WaitForCommand(request.MessageID);
                }

                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileInformation(out FileInformation result, object handle,
            FileInformationClass informationClass)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID) handle;

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                    result = ((QueryInfoResponse) response).GetFileInformation(informationClass);
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            var request = new SetInfoRequest();
            request.InfoType = InfoType.File;
            request.FileInformationClass = information.FileInformationClass;
            request.FileId = (FileID) handle;
            request.SetFileInformation(information);

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null) return response.Header.Status;

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result,
            FileSystemInformationClass informationClass)
        {
            result = null;
            var status = CreateFile(out var fileHandle, out var fileStatus, string.Empty,
                (AccessMask) DirectoryAccessMask.FILE_LIST_DIRECTORY |
                (AccessMask) DirectoryAccessMask.FILE_READ_ATTRIBUTES | AccessMask.SYNCHRONIZE, 0,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status != NTStatus.STATUS_SUCCESS) return status;

            status = GetFileSystemInformation(out result, fileHandle, informationClass);
            CloseFile(fileHandle);
            return status;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            throw new NotImplementedException();
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle,
            SecurityInformation securityInformation)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.Security;
            request.SecurityInformation = securityInformation;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID) handle;

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                    result = ((QueryInfoResponse) response).GetSecurityInformation();
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation,
            SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter,
            bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            throw new NotImplementedException();
        }

        public NTStatus Cancel(object ioRequest)
        {
            throw new NotImplementedException();
        }

        public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output,
            int maxOutputLength)
        {
            output = null;
            var request = new IOCtlRequest();
            request.Header.CreditCharge = (ushort) Math.Ceiling((double) maxOutputLength / BytesPerCredit);
            request.CtlCode = ctlCode;
            request.IsFSCtl = true;
            request.FileId = (FileID) handle;
            request.Input = input;
            request.MaxOutputResponse = (uint) maxOutputLength;
            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if ((response.Header.Status == NTStatus.STATUS_SUCCESS ||
                     response.Header.Status == NTStatus.STATUS_BUFFER_OVERFLOW) &&
                    response is IOCtlResponse) output = ((IOCtlResponse) response).Output;
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        public NTStatus Disconnect()
        {
            var request = new TreeDisconnectRequest();
            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null) return response.Header.Status;

            return NTStatus.STATUS_INVALID_SMB;
        }

        public uint MaxReadSize => m_client.MaxReadSize;

        public uint MaxWriteSize => m_client.MaxWriteSize;

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, object handle,
            FileSystemInformationClass informationClass)
        {
            result = null;
            var request = new QueryInfoRequest();
            request.InfoType = InfoType.FileSystem;
            request.FileSystemInformationClass = informationClass;
            request.OutputBufferLength = 4096;
            request.FileId = (FileID) handle;

            TrySendCommand(request);
            var response = m_client.WaitForCommand(request.MessageID);
            if (response != null)
            {
                if (response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryInfoResponse)
                    result = ((QueryInfoResponse) response).GetFileSystemInformation(informationClass);
                return response.Header.Status;
            }

            return NTStatus.STATUS_INVALID_SMB;
        }

        private void TrySendCommand(SMB2Command request)
        {
            request.Header.TreeID = m_treeID;
            m_client.TrySendCommand(request, m_encryptShareData);
        }

        private static FileStatus ToFileStatus(CreateAction createAction)
        {
            switch (createAction)
            {
                case CreateAction.FILE_SUPERSEDED:
                    return FileStatus.FILE_SUPERSEDED;
                case CreateAction.FILE_OPENED:
                    return FileStatus.FILE_OPENED;
                case CreateAction.FILE_CREATED:
                    return FileStatus.FILE_CREATED;
                case CreateAction.FILE_OVERWRITTEN:
                    return FileStatus.FILE_OVERWRITTEN;
                default:
                    return FileStatus.FILE_OPENED;
            }
        }
    }
}