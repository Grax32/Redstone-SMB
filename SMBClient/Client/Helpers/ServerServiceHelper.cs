/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using SMBLibrary.Enums;
using SMBLibrary.NTFileStore;
using SMBLibrary.NTFileStore.Enums;
using SMBLibrary.RPC.Enums;
using SMBLibrary.RPC.EnumStructures;
using SMBLibrary.RPC.PDU;
using SMBLibrary.Services.ServerService;
using SMBLibrary.Services.ServerService.Enums;
using SMBLibrary.Services.ServerService.EnumStructures;
using SMBLibrary.Services.ServerService.Structures.ShareInfo;
using SMBLibrary.Utilities.ByteUtils;
using ByteUtils = SMBLibrary.Utilities.ByteUtils.ByteUtils;

namespace SMBLibrary.Client.Helpers
{
    public class ServerServiceHelper
    {
        public static List<string> ListShares(INTFileStore namedPipeShare, ShareType? shareType, out NTStatus status)
        {
            object pipeHandle;
            int maxTransmitFragmentSize;
            status = NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName,
                ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion, out pipeHandle,
                out maxTransmitFragmentSize);
            if (status != NTStatus.STATUS_SUCCESS) return null;

            var shareEnumRequest = new NetrShareEnumRequest();
            shareEnumRequest.InfoStruct = new ShareEnum();
            shareEnumRequest.InfoStruct.Level = 1;
            shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
            shareEnumRequest.PreferedMaximumLength = uint.MaxValue;
            shareEnumRequest.ServerName = "*";
            var requestPDU = new RequestPDU
            {
                Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment,
                DataRepresentation =
                {
                    CharacterFormat = CharacterFormat.ASCII,
                    ByteOrder = ByteOrder.LittleEndian,
                    FloatingPointRepresentation = FloatingPointRepresentation.IEEE
                },
                OpNum = (ushort) ServerServiceOpName.NetrShareEnum,
                Data = shareEnumRequest.GetBytes()
            };
            requestPDU.AllocationHint = (uint) requestPDU.Data.Length;
            var input = requestPDU.GetBytes();
            var maxOutputLength = maxTransmitFragmentSize;
            status = namedPipeShare.DeviceIOControl(pipeHandle, (uint) IoControlCode.FSCTL_PIPE_TRANSCEIVE, input,
                out var output, maxOutputLength);
            if (status != NTStatus.STATUS_SUCCESS) return null;
            var responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                status = NTStatus.STATUS_NOT_SUPPORTED;
                return null;
            }

            var responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                status = namedPipeShare.ReadFile(out output, pipeHandle, 0, maxOutputLength);
                if (status != NTStatus.STATUS_SUCCESS) return null;
                responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return null;
                }

                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }

            namedPipeShare.CloseFile(pipeHandle);
            var shareEnumResponse = new NetrShareEnumResponse(responseData);
            var shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
            if (shareInfo1 == null || shareInfo1.Entries == null)
            {
                if (shareEnumResponse.Result == Win32Error.ERROR_ACCESS_DENIED)
                    status = NTStatus.STATUS_ACCESS_DENIED;
                else
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                return null;
            }

            var result = new List<string>();
            foreach (var entry in shareInfo1.Entries)
                if (!shareType.HasValue || shareType.Value == entry.ShareType.ShareType)
                    result.Add(entry.NetName.Value);
            return result;
        }
    }
}