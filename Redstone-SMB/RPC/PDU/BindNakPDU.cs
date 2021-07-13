/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.Enums;
using RedstoneSmb.RPC.Structures;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.PDU
{
    /// <summary>
    ///     rpcconn_bind_nak_hdr_t
    /// </summary>
    public class BindNakPdu : Rpcpdu
    {
        public const int BindNakFieldsFixedLength = 2;

        public RejectionReason RejectReason; // provider_reject_reason
        public VersionsSupported Versions; // versions

        public BindNakPdu()
        {
            PacketType = PacketTypeName.BindNak;
        }

        public BindNakPdu(byte[] buffer, int offset) : base(buffer, offset)
        {
            var startOffset = offset;
            offset += CommonFieldsLength;
            RejectReason = (RejectionReason) LittleEndianReader.ReadUInt16(buffer, ref offset);
            Versions = new VersionsSupported(buffer, offset);
        }

        public override int Length
        {
            get
            {
                var length = CommonFieldsLength + BindNakFieldsFixedLength;
                if (Versions != null) length += Versions.Length;
                return length;
            }
        }

        public override byte[] GetBytes()
        {
            var buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            var offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) RejectReason);
            Versions.WriteBytes(buffer, offset);

            return buffer;
        }
    }
}