/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.Enums;
using RedstoneSmb.SMB2.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 ERROR Response
    /// </summary>
    public class ErrorResponse : Smb2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;
        private uint _byteCount;
        public byte ErrorContextCount;
        public byte[] ErrorData = new byte[0];
        public byte Reserved;

        private readonly ushort _structureSize;

        public ErrorResponse(Smb2CommandName commandName) : base(commandName)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public ErrorResponse(Smb2CommandName commandName, NtStatus status) : base(commandName)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
            Header.Status = status;
        }

        public ErrorResponse(Smb2CommandName commandName, NtStatus status, byte[] errorData) : base(commandName)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
            Header.Status = status;
            ErrorData = errorData;
        }

        public ErrorResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            ErrorContextCount = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            _byteCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            ErrorData = ByteReader.ReadBytes(buffer, offset + Smb2Header.Length + 8, (int) _byteCount);
        }

        public override int CommandLength =>
            // If the ByteCount field is zero then the server MUST supply an ErrorData field that is one byte in length
            FixedSize + Math.Max(ErrorData.Length, 1);

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _byteCount = (uint) ErrorData.Length;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, ErrorContextCount);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, _byteCount);
            if (ErrorData.Length > 0)
                ByteWriter.WriteBytes(buffer, offset + 8, ErrorData);
            else
                // If the ByteCount field is zero then the server MUST supply an ErrorData field that is one byte in length, and SHOULD set that byte to zero
                ByteWriter.WriteBytes(buffer, offset + 8, new byte[1]);
        }
    }
}