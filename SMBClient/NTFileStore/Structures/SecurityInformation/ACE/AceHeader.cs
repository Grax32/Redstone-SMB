/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NTFileStore.Structures.SecurityInformation.ACE.Enums;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.NTFileStore.Structures.SecurityInformation.ACE
{
    /// <summary>
    ///     [MS-DTYP] ACE_HEADER
    /// </summary>
    public class AceHeader
    {
        public const int Length = 4;
        public AceFlags AceFlags;
        public ushort AceSize;

        public AceType AceType;

        public AceHeader()
        {
        }

        public AceHeader(byte[] buffer, int offset)
        {
            AceType = (AceType) ByteReader.ReadByte(buffer, offset + 0);
            AceFlags = (AceFlags) ByteReader.ReadByte(buffer, offset + 1);
            AceSize = LittleEndianConverter.ToUInt16(buffer, offset + 2);
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            ByteWriter.WriteByte(buffer, ref offset, (byte) AceType);
            ByteWriter.WriteByte(buffer, ref offset, (byte) AceFlags);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, AceSize);
        }
    }
}