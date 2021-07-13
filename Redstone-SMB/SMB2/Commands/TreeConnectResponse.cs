/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.AccessMask;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Enums.TreeConnect;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 TREE_CONNECT Response
    /// </summary>
    public class TreeConnectResponse : Smb2Command
    {
        public const int DeclaredSize = 16;
        public ShareCapabilities Capabilities;
        public AccessMask MaximalAccess;
        public byte Reserved;
        public ShareFlags ShareFlags;
        public ShareType ShareType;

        private readonly ushort _structureSize;

        public TreeConnectResponse() : base(Smb2CommandName.TreeConnect)
        {
            Header.IsResponse = true;
            _structureSize = DeclaredSize;
        }

        public TreeConnectResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            ShareType = (ShareType) ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            ShareFlags = (ShareFlags) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Capabilities = (ShareCapabilities) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 8);
            MaximalAccess = (AccessMask) LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
        }

        public override int CommandLength => DeclaredSize;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            ByteWriter.WriteByte(buffer, offset + 2, (byte) ShareType);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint) ShareFlags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, (uint) Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, (uint) MaximalAccess);
        }
    }
}