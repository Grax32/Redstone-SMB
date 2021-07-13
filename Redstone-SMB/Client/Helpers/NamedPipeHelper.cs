/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.Enums;
using RedstoneSmb.NTFileStore;
using RedstoneSmb.NTFileStore.Enums;
using RedstoneSmb.NTFileStore.Enums.AccessMask;
using RedstoneSmb.NTFileStore.Enums.NtCreateFile;
using RedstoneSmb.RPC.Enums;
using RedstoneSmb.RPC.EnumStructures;
using RedstoneSmb.RPC.PDU;
using RedstoneSmb.RPC.Structures;
using RedstoneSmb.Services;

namespace RedstoneSmb.Client.Helpers
{
    public class NamedPipeHelper
    {
        public static NtStatus BindPipe(INtFileStore namedPipeShare, string pipeName, Guid interfaceGuid,
            uint interfaceVersion, out object pipeHandle, out int maxTransmitFragmentSize)
        {
            maxTransmitFragmentSize = 0;
            FileStatus fileStatus;
            var status = namedPipeShare.CreateFile(out pipeHandle, out fileStatus, pipeName,
                (AccessMask) (FileAccessMask.FileReadData | FileAccessMask.FileWriteData), 0,
                ShareAccess.Read | ShareAccess.Write, CreateDisposition.FileOpen, 0, null);
            if (status != NtStatus.StatusSuccess) return status;
            var bindPdu = new BindPdu();
            bindPdu.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindPdu.DataRepresentation.CharacterFormat = CharacterFormat.Ascii;
            bindPdu.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            bindPdu.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.Ieee;
            bindPdu.MaxTransmitFragmentSize = 5680;
            bindPdu.MaxReceiveFragmentSize = 5680;

            var serviceContext = new ContextElement();
            serviceContext.AbstractSyntax = new SyntaxId(interfaceGuid, interfaceVersion);
            serviceContext.TransferSyntaxList.Add(new SyntaxId(RemoteServiceHelper.NdrTransferSyntaxIdentifier,
                RemoteServiceHelper.NdrTransferSyntaxVersion));

            bindPdu.ContextList.Add(serviceContext);

            var input = bindPdu.GetBytes();
            byte[] output;
            status = namedPipeShare.DeviceIoControl(pipeHandle, (uint) IoControlCode.FsctlPipeTransceive, input,
                out output, 4096);
            if (status != NtStatus.StatusSuccess) return status;
            var bindAckPdu = Rpcpdu.GetPdu(output, 0) as BindAckPdu;
            if (bindAckPdu == null) return NtStatus.StatusNotSupported;

            maxTransmitFragmentSize = bindAckPdu.MaxTransmitFragmentSize;
            return NtStatus.StatusSuccess;
        }
    }
}