/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using SMBLibrary.Utilities.Conversion;

namespace SMBLibrary.Utilities.ByteUtils
{
    public class LittleEndianReader
    {
        public static ushort ReadUInt16(byte[] buffer, ref int offset)
        {
            offset += 2;
            return LittleEndianConverter.ToUInt16(buffer, offset - 2);
        }

        public static uint ReadUInt32(byte[] buffer, ref int offset)
        {
            offset += 4;
            return LittleEndianConverter.ToUInt32(buffer, offset - 4);
        }

        public static Guid ReadGuid(byte[] buffer, ref int offset)
        {
            offset += 16;
            return LittleEndianConverter.ToGuid(buffer, offset - 16);
        }
    }
}