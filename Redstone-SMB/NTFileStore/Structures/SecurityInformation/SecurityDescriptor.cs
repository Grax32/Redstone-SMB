/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Structures.SecurityInformation.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation
{
    /// <summary>
    ///     [MS-DTYP] SECURITY_DESCRIPTOR
    /// </summary>
    public class SecurityDescriptor
    {
        public const int FixedLength = 20;
        public SecurityDescriptorControl Control;
        public Acl Dacl;

        public Sid GroupSid;

        // uint OffsetOwner;
        // uint OffsetGroup;
        // uint OffsetSacl;
        // uint OffsetDacl;
        public Sid OwnerSid;

        public byte Revision;
        public Acl Sacl;
        public byte Sbz1;

        public SecurityDescriptor()
        {
            Revision = 0x01;
        }

        public SecurityDescriptor(byte[] buffer, int offset)
        {
            Revision = ByteReader.ReadByte(buffer, ref offset);
            Sbz1 = ByteReader.ReadByte(buffer, ref offset);
            Control = (SecurityDescriptorControl) LittleEndianReader.ReadUInt16(buffer, ref offset);
            var offsetOwner = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var offsetGroup = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var offsetSacl = LittleEndianReader.ReadUInt32(buffer, ref offset);
            var offsetDacl = LittleEndianReader.ReadUInt32(buffer, ref offset);
            if (offsetOwner != 0) OwnerSid = new Sid(buffer, (int) offsetOwner);

            if (offsetGroup != 0) GroupSid = new Sid(buffer, (int) offsetGroup);

            if (offsetSacl != 0) Sacl = new Acl(buffer, (int) offsetSacl);

            if (offsetDacl != 0) Dacl = new Acl(buffer, (int) offsetDacl);
        }

        public int Length
        {
            get
            {
                var length = FixedLength;
                if (OwnerSid != null) length += OwnerSid.Length;

                if (GroupSid != null) length += GroupSid.Length;

                if (Sacl != null) length += Sacl.Length;

                if (Dacl != null) length += Dacl.Length;

                return length;
            }
        }

        public byte[] GetBytes()
        {
            var buffer = new byte[Length];
            uint offsetOwner = 0;
            uint offsetGroup = 0;
            uint offsetSacl = 0;
            uint offsetDacl = 0;
            var offset = FixedLength;
            if (OwnerSid != null)
            {
                offsetOwner = (uint) offset;
                offset += OwnerSid.Length;
            }

            if (GroupSid != null)
            {
                offsetGroup = (uint) offset;
                offset += GroupSid.Length;
            }

            if (Sacl != null)
            {
                offsetSacl = (uint) offset;
                offset += Sacl.Length;
            }

            if (Dacl != null)
            {
                offsetDacl = (uint) offset;
                offset += Dacl.Length;
            }

            offset = 0;
            ByteWriter.WriteByte(buffer, ref offset, Revision);
            ByteWriter.WriteByte(buffer, ref offset, Sbz1);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) Control);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetOwner);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetGroup);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetSacl);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetDacl);
            if (OwnerSid != null) OwnerSid.WriteBytes(buffer, ref offset);

            if (GroupSid != null) GroupSid.WriteBytes(buffer, ref offset);

            if (Sacl != null) Sacl.WriteBytes(buffer, ref offset);

            if (Dacl != null) Dacl.WriteBytes(buffer, ref offset);

            return buffer;
        }
    }
}