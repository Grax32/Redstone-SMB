/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.Enums;
using RedstoneSmb.RPC.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.PDU
{
    /// <summary>
    ///     rpcconn_bind_hdr_t
    /// </summary>
    public class BindPdu : Rpcpdu
    {
        public const int BindFieldsFixedLength = 8;
        public uint AssociationGroupId; // assoc_group_id
        public byte[] AuthVerifier;
        public ContextList ContextList;
        public ushort MaxReceiveFragmentSize; // max_recv_frag

        public ushort MaxTransmitFragmentSize; // max_xmit_frag

        public BindPdu()
        {
            PacketType = PacketTypeName.Bind;
            ContextList = new ContextList();
            AuthVerifier = new byte[0];
        }

        public BindPdu(byte[] buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            MaxTransmitFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            MaxReceiveFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            AssociationGroupId = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextList = new ContextList(buffer, offset);
            offset += ContextList.Length;
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override int Length => CommonFieldsLength + BindFieldsFixedLength + ContextList.Length + AuthLength;

        public override byte[] GetBytes()
        {
            AuthLength = (ushort) AuthVerifier.Length;
            var buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxTransmitFragmentSize);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxReceiveFragmentSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, AssociationGroupId);
            ContextList.WriteBytes(buffer, ref offset);
            ByteWriter.WriteBytes(buffer, offset, AuthVerifier);

            return buffer;
        }
    }
}