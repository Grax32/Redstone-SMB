/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using RedstoneSmb.Enums;
using RedstoneSmb.NTFileStore;
using RedstoneSmb.NTFileStore.Enums;
using RedstoneSmb.RPC.Enums;
using RedstoneSmb.RPC.EnumStructures;
using RedstoneSmb.RPC.PDU;
using RedstoneSmb.Services.ServerService;
using RedstoneSmb.Services.ServerService.Enums;
using RedstoneSmb.Services.ServerService.EnumStructures;
using RedstoneSmb.Services.ServerService.Structures.ShareInfo;
using ByteUtils = RedstoneSmb.Utilities.ByteUtils.ByteUtils;

namespace RedstoneSmb.Client.Helpers
{
    public class ServerServiceHelper
    {
        public static List<string> ListShares(INtFileStore namedPipeShare, ShareType? shareType, out NtStatus status)
        {
            object pipeHandle;
            int maxTransmitFragmentSize;
            status = NamedPipeHelper.BindPipe(namedPipeShare, ServerService.ServicePipeName,
                ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion, out pipeHandle,
                out maxTransmitFragmentSize);
            if (status != NtStatus.StatusSuccess) return null;

            var shareEnumRequest = new NetrShareEnumRequest();
            shareEnumRequest.InfoStruct = new ShareEnum();
            shareEnumRequest.InfoStruct.Level = 1;
            shareEnumRequest.InfoStruct.Info = new ShareInfo1Container();
            shareEnumRequest.PreferedMaximumLength = uint.MaxValue;
            shareEnumRequest.ServerName = "*";
            var requestPdu = new RequestPdu
            {
                Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment,
                DataRepresentation =
                {
                    CharacterFormat = CharacterFormat.Ascii,
                    ByteOrder = ByteOrder.LittleEndian,
                    FloatingPointRepresentation = FloatingPointRepresentation.Ieee
                },
                OpNum = (ushort) ServerServiceOpName.NetrShareEnum,
                Data = shareEnumRequest.GetBytes()
            };
            requestPdu.AllocationHint = (uint) requestPdu.Data.Length;
            var input = requestPdu.GetBytes();
            var maxOutputLength = maxTransmitFragmentSize;
            status = namedPipeShare.DeviceIoControl(pipeHandle, (uint) IoControlCode.FsctlPipeTransceive, input,
                out var output, maxOutputLength);
            if (status != NtStatus.StatusSuccess) return null;
            var responsePdu = Rpcpdu.GetPdu(output, 0) as ResponsePdu;
            if (responsePdu == null)
            {
                status = NtStatus.StatusNotSupported;
                return null;
            }

            var responseData = responsePdu.Data;
            while ((responsePdu.Flags & PacketFlags.LastFragment) == 0)
            {
                status = namedPipeShare.ReadFile(out output, pipeHandle, 0, maxOutputLength);
                if (status != NtStatus.StatusSuccess) return null;
                responsePdu = Rpcpdu.GetPdu(output, 0) as ResponsePdu;
                if (responsePdu == null)
                {
                    status = NtStatus.StatusNotSupported;
                    return null;
                }

                responseData = ByteUtils.Concatenate(responseData, responsePdu.Data);
            }

            namedPipeShare.CloseFile(pipeHandle);
            var shareEnumResponse = new NetrShareEnumResponse(responseData);
            var shareInfo1 = shareEnumResponse.InfoStruct.Info as ShareInfo1Container;
            if (shareInfo1 == null || shareInfo1.Entries == null)
            {
                if (shareEnumResponse.Result == Win32Error.ErrorAccessDenied)
                    status = NtStatus.StatusAccessDenied;
                else
                    status = NtStatus.StatusNotSupported;
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