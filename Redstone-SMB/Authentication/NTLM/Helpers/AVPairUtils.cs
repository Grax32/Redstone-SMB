/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.Text;
using SMBLibrary.Authentication.NTLM.Structures.Enums;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using SMBLibrary.Utilities.Generics;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianReader = SMBLibrary.Utilities.ByteUtils.LittleEndianReader;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.Authentication.NTLM.Helpers
{
    public class AVPairUtils
    {
        public static Utilities.Generics.KeyValuePairList<AVPairKey, byte[]> GetAVPairSequence(string domainName, string computerName)
        {
            var pairs = new Utilities.Generics.KeyValuePairList<AVPairKey, byte[]>();
            pairs.Add(AVPairKey.NbDomainName, Encoding.Unicode.GetBytes(domainName));
            pairs.Add(AVPairKey.NbComputerName, Encoding.Unicode.GetBytes(computerName));
            return pairs;
        }

        public static byte[] GetAVPairSequenceBytes(Utilities.Generics.KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            var length = GetAVPairSequenceLength(pairs);
            var result = new byte[length];
            var offset = 0;
            WriteAVPairSequence(result, ref offset, pairs);
            return result;
        }

        public static int GetAVPairSequenceLength(Utilities.Generics.KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            var length = 0;
            foreach (var pair in pairs) length += 4 + pair.Value.Length;
            return length + 4;
        }

        public static void WriteAVPairSequence(byte[] buffer, ref int offset, Utilities.Generics.KeyValuePairList<AVPairKey, byte[]> pairs)
        {
            foreach (var pair in pairs) WriteAVPair(buffer, ref offset, pair.Key, pair.Value);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) AVPairKey.EOL);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, 0);
        }

        private static void WriteAVPair(byte[] buffer, ref int offset, AVPairKey key, byte[] value)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) key);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort) value.Length);
            ByteWriter.WriteBytes(buffer, ref offset, value);
        }

        public static Utilities.Generics.KeyValuePairList<AVPairKey, byte[]> ReadAVPairSequence(byte[] buffer, int offset)
        {
            var result = new Utilities.Generics.KeyValuePairList<AVPairKey, byte[]>();
            var key = (AVPairKey) LittleEndianConverter.ToUInt16(buffer, offset);
            while (key != AVPairKey.EOL)
            {
                var pair = ReadAVPair(buffer, ref offset);
                result.Add(pair);
                key = (AVPairKey) LittleEndianConverter.ToUInt16(buffer, offset);
            }

            return result;
        }

        private static KeyValuePair<AVPairKey, byte[]> ReadAVPair(byte[] buffer, ref int offset)
        {
            var key = (AVPairKey) LittleEndianReader.ReadUInt16(buffer, ref offset);
            var length = LittleEndianReader.ReadUInt16(buffer, ref offset);
            var value = ByteReader.ReadBytes(buffer, ref offset, length);
            return new KeyValuePair<AVPairKey, byte[]>(key, value);
        }
    }
}