/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using RedstoneSmb.NTFileStore.Structures.FileInformation.Set;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.Helpers
{
    public class FileTimeHelper
    {
        public static readonly DateTime MinFileTimeValue = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static DateTime ReadFileTime(byte[] buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            
            if (span >= 0)
                return DateTime.FromFileTimeUtc(span);
            
            throw new InvalidDataException("FILETIME cannot be negative");
        }

        public static DateTime ReadFileTime(byte[] buffer, ref int offset)
        {
            offset += 8;
            return ReadFileTime(buffer, offset - 8);
        }

        public static void WriteFileTime(byte[] buffer, int offset, DateTime time)
        {
            var span = time.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }

        public static void WriteFileTime(byte[] buffer, ref int offset, DateTime time)
        {
            WriteFileTime(buffer, offset, time);
            offset += 8;
        }

        public static DateTime? ReadNullableFileTime(byte[] buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            if (span > 0)
                return DateTime.FromFileTimeUtc(span);
            if (span == 0)
                return null;
            throw new InvalidDataException("FILETIME cannot be negative");
        }

        public static DateTime? ReadNullableFileTime(byte[] buffer, ref int offset)
        {
            offset += 8;
            return ReadNullableFileTime(buffer, offset - 8);
        }

        public static void WriteFileTime(byte[] buffer, int offset, DateTime? time)
        {
            long span = 0;
            if (time.HasValue) span = time.Value.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }

        public static void WriteFileTime(byte[] buffer, ref int offset, DateTime? time)
        {
            WriteFileTime(buffer, offset, time);
            offset += 8;
        }

        /// <summary>
        ///     When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all
        ///     subsequent operations on the same file handle.
        /// </summary>
        public static SetFileTime ReadSetFileTime(byte[] buffer, int offset)
        {
            var span = LittleEndianConverter.ToInt64(buffer, offset);
            return SetFileTime.FromFileTimeUtc(span);
        }

        /// <summary>
        ///     When setting file attributes, a value of -1 indicates to the server that it MUST NOT change this attribute for all
        ///     subsequent operations on the same file handle.
        /// </summary>
        public static void WriteSetFileTime(byte[] buffer, int offset, SetFileTime time)
        {
            var span = time.ToFileTimeUtc();
            LittleEndianWriter.WriteInt64(buffer, offset, span);
        }
    }
}