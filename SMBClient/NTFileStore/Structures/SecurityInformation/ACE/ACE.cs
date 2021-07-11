/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using SMBLibrary.NTFileStore.Structures.SecurityInformation.ACE.Enums;
using SMBLibrary.Utilities.ByteUtils;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;

namespace SMBLibrary.NTFileStore.Structures.SecurityInformation.ACE
{
    /// <summary>
    ///     [MS-DTYP] ACE (Access Control Entry)
    /// </summary>
    public abstract class ACE
    {
        public abstract int Length { get; }

        public abstract void WriteBytes(byte[] buffer, ref int offset);

        public static ACE GetAce(byte[] buffer, int offset)
        {
            var aceType = (AceType) ByteReader.ReadByte(buffer, offset + 0);
            switch (aceType)
            {
                case AceType.ACCESS_ALLOWED_ACE_TYPE:
                    return new AccessAllowedACE(buffer, offset);
                default:
                    throw new NotImplementedException();
            }
        }
    }
}