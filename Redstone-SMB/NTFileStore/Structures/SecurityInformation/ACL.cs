/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation
{
    /// <summary>
    ///     [MS-DTYP] ACL (Access Control List)
    /// </summary>
    public class Acl : List<ACE.Ace>
    {
        public const int FixedLength = 8;

        public byte AclRevision;

        public byte Sbz1;

        // ushort AclSize;
        // ushort AceCount;
        public ushort Sbz2;

        public Acl()
        {
            AclRevision = 0x02;
        }

        public Acl(byte[] buffer, int offset)
        {
            AclRevision = ByteReader.ReadByte(buffer, offset + 0);
            Sbz1 = ByteReader.ReadByte(buffer, offset + 1);
            var aclSize = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            var aceCount = LittleEndianConverter.ToUInt16(buffer, offset + 4);
            Sbz2 = LittleEndianConverter.ToUInt16(buffer, offset + 6);

            offset += 8;
            for (var index = 0; index < aceCount; index++)
            {
                var ace = ACE.Ace.GetAce(buffer, offset);
                Add(ace);
                offset += ace.Length;
            }
        }

        public int Length
        {
            get
            {
                var length = FixedLength;
                foreach (var ace in this) length += ace.Length;
                return length;
            }
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            ByteWriter.WriteByte(buffer, ref offset, AclRevision);
            ByteWriter.WriteByte(buffer, ref offset, Sbz1);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) Length);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) Count);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, Sbz2);
            foreach (var ace in this) ace.WriteBytes(buffer, ref offset);
        }
    }
}