/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using SMBLibrary.Utilities.ByteUtils;
using SMBLibrary.Utilities.Conversion;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = SMBLibrary.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = SMBLibrary.Utilities.ByteUtils.LittleEndianWriter;

namespace SMBLibrary.SMB2.Structures
{
    /// <summary>
    ///     [MS-SMB2] 2.2.13.2 - SMB2_CREATE_CONTEXT
    /// </summary>
    public class CreateContext
    {
        public const int FixedLength = 16;
        public byte[] Data = new byte[0];
        private uint DataLength;
        private ushort DataOffset; // The offset from the beginning of this structure to the 8-byte aligned data payload
        public string Name = string.Empty;
        private ushort NameLength;
        private ushort NameOffset; // The offset from the beginning of this structure to the 8-byte aligned name value

        /// <summary>
        ///     The offset from the beginning of this Create Context to the beginning of a subsequent 8-byte aligned Create
        ///     Context.
        ///     This field MUST be set to 0 if there are no subsequent contexts.
        /// </summary>
        public uint Next;

        public ushort Reserved;

        public CreateContext()
        {
        }

        public CreateContext(byte[] buffer, int offset)
        {
            Next = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            NameOffset = LittleEndianConverter.ToUInt16(buffer, offset + 4);
            NameLength = LittleEndianConverter.ToUInt16(buffer, offset + 6);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + 8);
            DataOffset = LittleEndianConverter.ToUInt16(buffer, offset + 10);
            DataLength = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            if (NameLength > 0) Name = ByteReader.ReadUTF16String(buffer, offset + NameOffset, NameLength / 2);
            if (DataLength > 0) Data = ByteReader.ReadBytes(buffer, offset + DataOffset, (int) DataLength);
        }

        public int Length
        {
            get
            {
                if (Data.Length > 0)
                {
                    var paddedNameLength = (int) Math.Ceiling((double) (Name.Length * 2) / 8) * 8;
                    return FixedLength + paddedNameLength + Data.Length;
                }

                return FixedLength + Name.Length * 2;
            }
        }

        private void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, Next);
            NameOffset = 0;
            NameLength = (ushort) (Name.Length * 2);
            if (Name.Length > 0) NameOffset = FixedLength;
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, NameOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, NameLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 8, Reserved);
            DataOffset = 0;
            DataLength = (uint) Data.Length;
            if (Data.Length > 0)
            {
                var paddedNameLength = (int) Math.Ceiling((double) (Name.Length * 2) / 8) * 8;
                DataOffset = (ushort) (FixedLength + paddedNameLength);
            }

            LittleEndianWriter.WriteUInt16(buffer, offset + 10, DataOffset);
            ByteWriter.WriteUTF16String(buffer, NameOffset, Name);
            ByteWriter.WriteBytes(buffer, DataOffset, Data);
        }

        public static List<CreateContext> ReadCreateContextList(byte[] buffer, int offset)
        {
            var result = new List<CreateContext>();
            CreateContext createContext;
            do
            {
                createContext = new CreateContext(buffer, offset);
                result.Add(createContext);
                offset += (int) createContext.Next;
            } while (createContext.Next != 0);

            return result;
        }

        public static void WriteCreateContextList(byte[] buffer, int offset, List<CreateContext> createContexts)
        {
            for (var index = 0; index < createContexts.Count; index++)
            {
                var createContext = createContexts[index];
                var length = createContext.Length;
                var paddedLength = (int) Math.Ceiling((double) length / 8) * 8;
                if (index < createContexts.Count - 1)
                    createContext.Next = (uint) paddedLength;
                else
                    createContext.Next = 0;
                createContext.WriteBytes(buffer, offset);
                offset += paddedLength;
            }
        }

        public static int GetCreateContextListLength(List<CreateContext> createContexts)
        {
            var result = 0;
            for (var index = 0; index < createContexts.Count; index++)
            {
                var createContext = createContexts[index];
                var length = createContext.Length;
                if (index < createContexts.Count - 1)
                {
                    var paddedLength = (int) Math.Ceiling((double) length / 8) * 8;
                    result += paddedLength;
                }
                else
                {
                    result += length;
                }
            }

            return result;
        }
    }
}