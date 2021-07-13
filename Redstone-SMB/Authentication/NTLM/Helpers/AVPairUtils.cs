/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Text;
using RedstoneSmb.Authentication.NTLM.Structures.Enums;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.Authentication.NTLM.Helpers
{
    public class AvPairUtils
    {
        public static Utilities.Generics.KeyValuePairList<AvPairKey, byte[]> GetAvPairSequence(string domainName, string computerName)
        {
            var pairs = new Utilities.Generics.KeyValuePairList<AvPairKey, byte[]>();
            pairs.Add(AvPairKey.NbDomainName, Encoding.Unicode.GetBytes(domainName));
            pairs.Add(AvPairKey.NbComputerName, Encoding.Unicode.GetBytes(computerName));
            return pairs;
        }

        public static byte[] GetAvPairSequenceBytes(Utilities.Generics.KeyValuePairList<AvPairKey, byte[]> pairs)
        {
            var length = GetAvPairSequenceLength(pairs);
            var result = new byte[length];
            var offset = 0;
            WriteAvPairSequence(result, ref offset, pairs);
            return result;
        }

        public static int GetAvPairSequenceLength(Utilities.Generics.KeyValuePairList<AvPairKey, byte[]> pairs)
        {
            var length = 0;
            foreach (var pair in pairs) length += 4 + pair.Value.Length;
            return length + 4;
        }

        public static void WriteAvPairSequence(byte[] buffer, ref int offset, Utilities.Generics.KeyValuePairList<AvPairKey, byte[]> pairs)
        {
            foreach (var pair in pairs) WriteAvPair(buffer, ref offset, pair.Key, pair.Value);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) AvPairKey.Eol);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, 0);
        }

        private static void WriteAvPair(byte[] buffer, ref int offset, AvPairKey key, byte[] value)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) key);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) value.Length);
            ByteWriter.WriteBytes(buffer, ref offset, value);
        }

        public static Utilities.Generics.KeyValuePairList<AvPairKey, byte[]> ReadAvPairSequence(byte[] buffer, int offset)
        {
            var result = new Utilities.Generics.KeyValuePairList<AvPairKey, byte[]>();
            var key = (AvPairKey) LittleEndianConverter.ToUInt16(buffer, offset);
            while (key != AvPairKey.Eol)
            {
                var pair = ReadAvPair(buffer, ref offset);
                result.Add(pair);
                key = (AvPairKey) LittleEndianConverter.ToUInt16(buffer, offset);
            }

            return result;
        }

        private static KeyValuePair<AvPairKey, byte[]> ReadAvPair(byte[] buffer, ref int offset)
        {
            var key = (AvPairKey) LittleEndianReader.ReadUInt16(buffer, ref offset);
            var length = LittleEndianReader.ReadUInt16(buffer, ref offset);
            var value = ByteReader.ReadBytes(buffer, ref offset, length);
            return new KeyValuePair<AvPairKey, byte[]>(key, value);
        }
    }
}