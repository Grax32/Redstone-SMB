/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.RPC.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.PDU
{
    /// <summary>
    ///     rpcconn_request_hdr_t
    /// </summary>
    public class RequestPdu : Rpcpdu
    {
        public const int RequestFieldsFixedLength = 8;

        public uint AllocationHint; // alloc_hint
        public byte[] AuthVerifier;
        public ushort ContextId;
        public byte[] Data;
        public Guid ObjectGuid; // Optional field
        public ushort OpNum;

        public RequestPdu()
        {
            PacketType = PacketTypeName.Request;
            AuthVerifier = new byte[0];
        }

        public RequestPdu(byte[] buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            AllocationHint = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextId = LittleEndianReader.ReadUInt16(buffer, ref offset);
            OpNum = LittleEndianReader.ReadUInt16(buffer, ref offset);
            if ((Flags & PacketFlags.ObjectUuid) > 0) ObjectGuid = LittleEndianReader.ReadGuid(buffer, ref offset);
            var dataLength = FragmentLength - AuthLength - offset;
            Data = ByteReader.ReadBytes(buffer, ref offset, dataLength);
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override int Length
        {
            get
            {
                var length = CommonFieldsLength + RequestFieldsFixedLength + Data.Length + AuthVerifier.Length;
                if ((Flags & PacketFlags.ObjectUuid) > 0) length += 16;
                return length;
            }
        }

        public override byte[] GetBytes()
        {
            AuthLength = (ushort) AuthVerifier.Length;
            var buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt32(buffer, ref offset, AllocationHint);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, ContextId);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, OpNum);
            if ((Flags & PacketFlags.ObjectUuid) > 0) LittleEndianWriter.WriteGuid(buffer, ref offset, ObjectGuid);
            ByteWriter.WriteBytes(buffer, ref offset, Data);
            ByteWriter.WriteBytes(buffer, ref offset, AuthVerifier);
            return buffer;
        }
    }
}