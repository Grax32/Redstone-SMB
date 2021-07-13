/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Text;

namespace RedstoneSmb.RPC.NDR
{
    public class NdrUnicodeString : INdrStructure
    {
        private readonly bool _mWriteNullTerminationCharacter;

        public string Value;

        public NdrUnicodeString() : this(string.Empty, true)
        {
        }

        public NdrUnicodeString(string value) : this(value, true)
        {
        }

        public NdrUnicodeString(string value, bool writeNullTerminationCharacter)
        {
            _mWriteNullTerminationCharacter = writeNullTerminationCharacter;
            Value = value;
        }

        public NdrUnicodeString(NdrParser parser)
        {
            Read(parser);
        }

        // 14.3.4.2 - Conformant and Varying Strings
        public void Read(NdrParser parser)
        {
            var maxCount = parser.ReadUInt32();
            // the offset from the first index of the string to the first index of the actual subset being passed
            var index = parser.ReadUInt32();
            // actualCount includes the null terminator
            var actualCount = parser.ReadUInt32();
            var builder = new StringBuilder();
            for (var position = 0; position < actualCount; position++) builder.Append((char) parser.ReadUInt16());
            Value = builder.ToString().TrimEnd('\0');
        }

        public void Write(NdrWriter writer)
        {
            var valueToWrite = string.Empty;
            if (Value != null) valueToWrite = Value;

            if (_mWriteNullTerminationCharacter) valueToWrite += '\0';

            var maxCount = (uint) valueToWrite.Length;
            writer.WriteUInt32(maxCount);
            // the offset from the first index of the string to the first index of the actual subset being passed
            uint index = 0;
            writer.WriteUInt32(index);
            var actualCount = (uint) valueToWrite.Length;
            writer.WriteUInt32(actualCount);
            for (var position = 0; position < valueToWrite.Length; position++)
                writer.WriteUInt16(valueToWrite[position]);
        }
    }
}