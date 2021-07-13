/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.SMB2.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 TREE_CONNECT Request
    /// </summary>
    public class TreeConnectRequest : Smb2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;
        public string Path = string.Empty;
        private ushort _pathLength;
        private ushort _pathOffset;
        public ushort Reserved;

        private readonly ushort _structureSize;

        public TreeConnectRequest() : base(Smb2CommandName.TreeConnect)
        {
            _structureSize = DeclaredSize;
        }

        public TreeConnectRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            _pathOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 4);
            _pathLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 6);
            if (_pathLength > 0) Path = ByteReader.ReadUtf16String(buffer, offset + _pathOffset, _pathLength / 2);
        }

        public override int CommandLength => 8 + Path.Length * 2;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            _pathOffset = 0;
            _pathLength = (ushort) (Path.Length * 2);
            if (Path.Length > 0) _pathOffset = Smb2Header.Length + 8;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, _pathOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, _pathLength);
            if (Path.Length > 0) ByteWriter.WriteUtf16String(buffer, offset + 8, Path);
        }
    }
}