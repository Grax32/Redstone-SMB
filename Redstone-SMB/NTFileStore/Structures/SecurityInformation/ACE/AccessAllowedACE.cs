/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.NTFileStore.Enums.AccessMask;
using RedstoneSmb.NTFileStore.Structures.SecurityInformation.ACE.Enums;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation.ACE
{
    /// <summary>
    ///     [MS-DTYP] ACCESS_ALLOWED_ACE
    /// </summary>
    public class AccessAllowedAce : Ace
    {
        public const int FixedLength = 8;

        public AceHeader Header;
        public AccessMask Mask;
        public Sid Sid;

        public AccessAllowedAce()
        {
            Header = new AceHeader();
            Header.AceType = AceType.AccessAllowedAceType;
        }

        public AccessAllowedAce(byte[] buffer, int offset)
        {
            Header = new AceHeader(buffer, offset + 0);
            Mask = (AccessMask) LittleEndianConverter.ToUInt32(buffer, offset + 4);
            Sid = new Sid(buffer, offset + 8);
        }

        public override int Length => FixedLength + Sid.Length;

        public override void WriteBytes(byte[] buffer, ref int offset)
        {
            Header.AceSize = (ushort) Length;
            Header.WriteBytes(buffer, ref offset);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint) Mask);
            Sid.WriteBytes(buffer, ref offset);
        }
    }
}