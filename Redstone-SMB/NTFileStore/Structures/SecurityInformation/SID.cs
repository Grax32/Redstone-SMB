/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation
{
    /// <summary>
    ///     [MS-DTYP] 2.4.2.2 - SID (Packet Representation)
    /// </summary>
    public class Sid
    {
        public const int FixedLength = 8;
        public static readonly byte[] WorldSidAuthority = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        public static readonly byte[] LocalSidAuthority = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
        public static readonly byte[] CreatorSidAuthority = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

        public static readonly byte[] SecurityNtAuthority = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

        // byte SubAuthorityCount;
        public byte[] IdentifierAuthority; // 6 bytes

        public byte Revision;
        public List<uint> SubAuthority = new List<uint>();

        public Sid()
        {
            Revision = 0x01;
        }

        public Sid(byte[] buffer, int offset)
        {
            Revision = ByteReader.ReadByte(buffer, ref offset);
            var subAuthorityCount = ByteReader.ReadByte(buffer, ref offset);
            IdentifierAuthority = ByteReader.ReadBytes(buffer, ref offset, 6);
            for (var index = 0; index < subAuthorityCount; index++)
            {
                var entry = LittleEndianReader.ReadUInt32(buffer, ref offset);
                SubAuthority.Add(entry);
            }
        }

        public int Length => FixedLength + SubAuthority.Count * 4;

        public static Sid Everyone
        {
            get
            {
                var sid = new Sid();
                sid.IdentifierAuthority = WorldSidAuthority;
                sid.SubAuthority.Add(0);
                return sid;
            }
        }

        public static Sid LocalSystem
        {
            get
            {
                var sid = new Sid();
                sid.IdentifierAuthority = SecurityNtAuthority;
                sid.SubAuthority.Add(18);
                return sid;
            }
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            var subAuthorityCount = (byte) SubAuthority.Count;
            ByteWriter.WriteByte(buffer, ref offset, Revision);
            ByteWriter.WriteByte(buffer, ref offset, subAuthorityCount);
            ByteWriter.WriteBytes(buffer, ref offset, IdentifierAuthority, 6);
            for (var index = 0; index < SubAuthority.Count; index++)
                LittleEndianWriter.WriteUInt32(buffer, ref offset, SubAuthority[index]);
        }
    }
}