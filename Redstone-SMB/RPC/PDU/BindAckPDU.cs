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
    ///     rpcconn_bind_ack_hdr_t
    /// </summary>
    public class BindAckPdu : Rpcpdu
    {
        public const int BindAckFieldsFixedLength = 8;
        public uint AssociationGroupId; // assoc_group_id
        public byte[] AuthVerifier;
        public ushort MaxReceiveFragmentSize; // max_recv_frag

        public ushort MaxTransmitFragmentSize; // max_xmit_frag

        // Padding (alignment to 4 byte boundary)
        public ResultList ResultList; // p_result_list
        public string SecondaryAddress; // sec_addr (port_any_t)

        public BindAckPdu()
        {
            PacketType = PacketTypeName.BindAck;
            SecondaryAddress = string.Empty;
            ResultList = new ResultList();
            AuthVerifier = new byte[0];
        }

        public BindAckPdu(byte[] buffer, int offset) : base(buffer, offset)
        {
            var startOffset = offset;
            offset += CommonFieldsLength;
            MaxTransmitFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            MaxReceiveFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            AssociationGroupId = LittleEndianReader.ReadUInt32(buffer, ref offset);
            SecondaryAddress = RpcHelper.ReadPortAddress(buffer, ref offset);
            var padding = (4 - (offset - startOffset) % 4) % 4;
            offset += padding;
            ResultList = new ResultList(buffer, offset);
            offset += ResultList.Length;
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override int Length
        {
            get
            {
                var padding = (4 - (SecondaryAddress.Length + 3) % 4) % 4;
                return CommonFieldsLength + BindAckFieldsFixedLength + SecondaryAddress.Length + 3 + padding +
                       ResultList.Length + AuthLength;
            }
        }

        public override byte[] GetBytes()
        {
            AuthLength = (ushort) AuthVerifier.Length;
            var padding = (4 - (SecondaryAddress.Length + 3) % 4) % 4;
            var buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxTransmitFragmentSize);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxReceiveFragmentSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, AssociationGroupId);
            RpcHelper.WritePortAddress(buffer, ref offset, SecondaryAddress);
            offset += padding;
            ResultList.WriteBytes(buffer, ref offset);
            ByteWriter.WriteBytes(buffer, offset, AuthVerifier);

            return buffer;
        }
    }
}