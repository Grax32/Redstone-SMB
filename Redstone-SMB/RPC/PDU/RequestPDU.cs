/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using SMBLibrary.RPC.Enums;
using SMBLibrary.Utilities.ByteUtils;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = SMBLibrary.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.RPC.PDU
{
    /// <summary>
    ///     rpcconn_request_hdr_t
    /// </summary>
    public class RequestPDU : RPCPDU
    {
        public const int RequestFieldsFixedLength = 8;

        public uint AllocationHint; // alloc_hint
        public byte[] AuthVerifier;
        public ushort ContextID;
        public byte[] Data;
        public Guid ObjectGuid; // Optional field
        public ushort OpNum;

        public RequestPDU()
        {
            PacketType = PacketTypeName.Request;
            AuthVerifier = new byte[0];
        }

        public RequestPDU(byte[] buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            AllocationHint = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            OpNum = LittleEndianReader.ReadUInt16(buffer, ref offset);
            if ((Flags & PacketFlags.ObjectUUID) > 0) ObjectGuid = LittleEndianReader.ReadGuid(buffer, ref offset);
            var dataLength = FragmentLength - AuthLength - offset;
            Data = ByteReader.ReadBytes(buffer, ref offset, dataLength);
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override int Length
        {
            get
            {
                var length = CommonFieldsLength + RequestFieldsFixedLength + Data.Length + AuthVerifier.Length;
                if ((Flags & PacketFlags.ObjectUUID) > 0) length += 16;
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
            LittleEndianWriter.WriteUInt16(buffer, ref offset, ContextID);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, OpNum);
            if ((Flags & PacketFlags.ObjectUUID) > 0) LittleEndianWriter.WriteGuid(buffer, ref offset, ObjectGuid);
            ByteWriter.WriteBytes(buffer, ref offset, Data);
            ByteWriter.WriteBytes(buffer, ref offset, AuthVerifier);
            return buffer;
        }
    }
}