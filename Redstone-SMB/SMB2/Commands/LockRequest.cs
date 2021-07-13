/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using RedstoneSmb.SMB2.Enums;
using RedstoneSmb.SMB2.Structures;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.SMB2.Commands
{
    /// <summary>
    ///     SMB2 LOCK Request
    /// </summary>
    public class LockRequest : Smb2Command
    {
        public const int DeclaredSize = 48;
        public FileId FileId;
        public List<LockElement> Locks;

        public uint LockSequenceIndex; // 28 bits

        // ushort LockCount;
        public byte Lsn; // 4 bits

        private readonly ushort _structureSize;

        public LockRequest() : base(Smb2CommandName.Lock)
        {
            _structureSize = DeclaredSize;
        }

        public LockRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            _structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            var lockCount = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            var temp = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            Lsn = (byte) (temp >> 28);
            LockSequenceIndex = temp & 0x0FFFFFFF;
            FileId = new FileId(buffer, offset + Smb2Header.Length + 8);
            Locks = LockElement.ReadLockList(buffer, offset + Smb2Header.Length + 24, lockCount);
        }

        public override int CommandLength => 48 + Locks.Count * LockElement.StructureLength;

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, _structureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort) Locks.Count);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4,
                ((uint) (Lsn & 0x0F) << 28) | LockSequenceIndex & 0x0FFFFFFF);
            FileId.WriteBytes(buffer, offset + 8);
            LockElement.WriteLockList(buffer, offset + 24, Locks);
        }
    }
}