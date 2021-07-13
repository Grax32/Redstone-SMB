/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 LOCK Response
    /// </summary>
    public class LockResponse : Smb2Command
    {
        public const int DeclaredSize = 4;
        public ushort Reserved;

        private readonly ushort _structureSize;

        public LockResponse() : base(Smb2CommandName.Lock)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public LockResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
        }

        public override int CommandLength => DeclaredSize;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
        }
    }
}