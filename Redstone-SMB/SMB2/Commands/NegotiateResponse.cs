/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Negotiate;
using RedstoneSmb.SMB2.Structures;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 NEGOTIATE Response
    /// </summary>
    public class NegotiateResponse : Smb2Command
    {
        public const int FixedSize = 64;
        public const int DeclaredSize = 65;
        public Capabilities Capabilities;
        public Smb2Dialect DialectRevision;
        public uint MaxReadSize;
        public uint MaxTransactSize;
        public uint MaxWriteSize;
        private ushort _negotiateContextCount;
        public List<NegotiateContext> NegotiateContextList = new List<NegotiateContext>();
        private uint _negotiateContextOffset;
        public byte[] SecurityBuffer = new byte[0];
        private ushort _securityBufferLength;
        private ushort _securityBufferOffset;
        public SecurityMode SecurityMode;
        public Guid ServerGuid;
        public DateTime ServerStartTime;

        private readonly ushort _structureSize;
        public DateTime SystemTime;

        public NegotiateResponse() : base(Smb2CommandName.Negotiate)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public NegotiateResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            SecurityMode = (SecurityMode) LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            DialectRevision = (Smb2Dialect) LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 4);
            _negotiateContextCount = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 6);
            ServerGuid = LittleEndianConverter.ToGuid(buffer, offset + Smb2Header.Length + 8);
            Capabilities = (Capabilities) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 24);
            MaxTransactSize = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            MaxReadSize = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            MaxWriteSize = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            SystemTime =
                DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 40));
            ServerStartTime =
                DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + Smb2Header.Length + 48));
            _securityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 56);
            _securityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 58);
            _negotiateContextOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 60);
            SecurityBuffer = ByteReader.ReadBytes(buffer, offset + _securityBufferOffset, _securityBufferLength);
            NegotiateContextList =
                NegotiateContext.ReadNegotiateContextList(buffer, (int) _negotiateContextOffset, _negotiateContextCount);
        }

        public override int CommandLength
        {
            get
            {
                if (NegotiateContextList.Count == 0)
                {
                    return FixedSize + SecurityBuffer.Length;
                }

                var paddedSecurityBufferLength = (int) Math.Ceiling((double) _securityBufferLength / 8) * 8;
                return FixedSize + paddedSecurityBufferLength +
                       NegotiateContext.GetNegotiateContextListLength(NegotiateContextList);
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _securityBufferOffset = 0;
            _securityBufferLength = (ushort) SecurityBuffer.Length;
            var paddedSecurityBufferLength = (int) Math.Ceiling((double) _securityBufferLength / 8) * 8;
            if (SecurityBuffer.Length > 0) _securityBufferOffset = Smb2Header.Length + FixedSize;
            _negotiateContextOffset = 0;
            _negotiateContextCount = (ushort) NegotiateContextList.Count;
            if (NegotiateContextList.Count > 0)
                // NegotiateContextList must be 8-byte aligned
                _negotiateContextOffset = (uint) (Smb2Header.Length + FixedSize + paddedSecurityBufferLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort) SecurityMode);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, (ushort) DialectRevision);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, _negotiateContextCount);
            LittleEndianWriter.WriteGuid(buffer, offset + 8, ServerGuid);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, (uint) Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, MaxTransactSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, MaxReadSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, MaxWriteSize);
            LittleEndianWriter.WriteInt64(buffer, offset + 40, SystemTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 48, ServerStartTime.ToFileTimeUtc());
            LittleEndianWriter.WriteUInt16(buffer, offset + 56, _securityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 58, _securityBufferLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, _negotiateContextOffset);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, SecurityBuffer);
            NegotiateContext.WriteNegotiateContextList(buffer, offset + FixedSize + paddedSecurityBufferLength,
                NegotiateContextList);
        }
    }
}