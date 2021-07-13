/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using RedstoneSmb.NTFileStore.Structures.SecurityInformation.ACE.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;

namespace RedstoneSmb.NTFileStore.Structures.SecurityInformation.ACE
{
    /// <summary>
    ///     [MS-DTYP] ACE (Access Control Entry)
    /// </summary>
    public abstract class Ace
    {
        public abstract int Length { get; }

        public abstract void WriteBytes(byte[] buffer, ref int offset);

        public static Ace GetAce(byte[] buffer, int offset)
        {
            var aceType = (AceType) ByteReader.ReadByte(buffer, offset + 0);
            switch (aceType)
            {
                case AceType.AccessAllowedAceType:
                    return new AccessAllowedAce(buffer, offset);
                default:
                    throw new NotImplementedException();
            }
        }
    }
}