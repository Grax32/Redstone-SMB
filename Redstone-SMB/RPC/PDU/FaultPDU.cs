/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.PDU
{
    /// <summary>
    ///     rpcconn_fault_hdr_t
    /// </summary>
    public class FaultPdu : Rpcpdu
    {
        public const int FaultFieldsLength = 16;

        public uint AllocationHint;
        public byte[] AuthVerifier;
        public byte CancelCount;
        public ushort ContextId;
        public byte[] Data;
        public byte Reserved;
        public uint Reserved2;
        public FaultStatus Status;

        public FaultPdu()
        {
            PacketType = PacketTypeName.Fault;
            Data = new byte[0];
            AuthVerifier = new byte[0];
        }

        public FaultPdu(byte[] buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            AllocationHint = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextId = LittleEndianReader.ReadUInt16(buffer, ref offset);
            CancelCount = ByteReader.ReadByte(buffer, ref offset);
            Reserved = ByteReader.ReadByte(buffer, ref offset);
            Status = (FaultStatus) LittleEndianReader.ReadUInt32(buffer, ref offset);
            Reserved2 = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var dataLength = FragmentLength - AuthLength - offset;
            Data = ByteReader.ReadBytes(buffer, ref offset, dataLength);
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override int Length => CommonFieldsLength + FaultFieldsLength + Data.Length + AuthVerifier.Length;

        public override byte[] GetBytes()
        {
            AuthLength = (ushort) AuthVerifier.Length;
            var buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt32(buffer, ref offset, AllocationHint);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, ContextId);
            ByteWriter.WriteByte(buffer, ref offset, CancelCount);
            ByteWriter.WriteByte(buffer, ref offset, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint) Status);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, Reserved2);
            ByteWriter.WriteBytes(buffer, ref offset, Data);
            ByteWriter.WriteBytes(buffer, ref offset, AuthVerifier);
            return buffer;
        }
    }
}