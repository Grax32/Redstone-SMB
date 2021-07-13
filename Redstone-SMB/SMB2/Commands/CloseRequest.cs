/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.Close;
using RedstoneSmb.SMB2.Structures;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 CLOSE Request
    /// </summary>
    public class CloseRequest : Smb2Command
    {
        public const int DeclaredSize = 24;
        public FileId FileId;
        public CloseFlags Flags;
        public uint Reserved;

        private readonly ushort _structureSize;

        public CloseRequest() : base(Smb2CommandName.Close)
        {
            _structureSize = DeclaredSize;
        }

        public CloseRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Flags = (CloseFlags) LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = new FileId(buffer, offset + Smb2Header.Length + 8);
        }

        public bool PostQueryAttributes => (Flags & CloseFlags.PostQueryAttributes) > 0;

        public override int CommandLength => DeclaredSize;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort) Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, Reserved);
            FileId.WriteBytes(buffer, offset + 8);
        }
    }
}