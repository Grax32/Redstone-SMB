/* Copyright (C) 2012-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Text;
using RedstoneSmb.Utilities.Conversion;

namespace RedstoneSmb.Utilities.ByteUtils
{
    public class ByteReader
    {
        public static byte ReadByte(byte[] buffer, int offset)
        {
            return buffer[offset];
        }

        public static byte ReadByte(byte[] buffer, ref int offset)
        {
            offset++;
            return buffer[offset - 1];
        }

        public static byte[] ReadBytes(byte[] buffer, int offset, int length)
        {
            var result = new byte[length];
            Array.Copy(buffer, offset, result, 0, length);
            return result;
        }

        public static byte[] ReadBytes(byte[] buffer, ref int offset, int length)
        {
            offset += length;
            return ReadBytes(buffer, offset - length, length);
        }

        /// <summary>
        ///     Will return the ANSI string stored in the buffer
        /// </summary>
        public static string ReadAnsiString(byte[] buffer, int offset, int count)
        {
            // ASCIIEncoding.ASCII.GetString will convert some values to '?' (byte value of 63)
            // Any codepage will do, but the only one that Mono supports is 28591.
            return Encoding.GetEncoding(28591).GetString(buffer, offset, count);
        }

        public static string ReadAnsiString(byte[] buffer, ref int offset, int count)
        {
            offset += count;
            return ReadAnsiString(buffer, offset - count, count);
        }

        public static string ReadUtf16String(byte[] buffer, int offset, int numberOfCharacters)
        {
            var numberOfBytes = numberOfCharacters * 2;
            return Encoding.Unicode.GetString(buffer, offset, numberOfBytes);
        }

        public static string ReadNullTerminatedUtf16String(byte[] buffer, int offset)
        {
            var builder = new StringBuilder();
            var c = (char) LittleEndianConverter.ToUInt16(buffer, offset);
            while (c != 0)
            {
                builder.Append(c);
                offset += 2;
                c = (char) LittleEndianConverter.ToUInt16(buffer, offset);
            }

            return builder.ToString();
        }
    }
}