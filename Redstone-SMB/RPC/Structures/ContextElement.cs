/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.Structures
{
    /// <summary>
    ///     p_cont_elem_t
    /// </summary>
    public class ContextElement // Presentation Context Element
    {
        public SyntaxId AbstractSyntax;

        public ushort ContextId;

        // byte NumberOfTransferSyntaxItems;
        public byte Reserved;
        public List<SyntaxId> TransferSyntaxList = new List<SyntaxId>();

        public ContextElement()
        {
        }

        public ContextElement(byte[] buffer, int offset)
        {
            ContextId = LittleEndianConverter.ToUInt16(buffer, offset + 0);
            var numberOfTransferSyntaxItems = ByteReader.ReadByte(buffer, offset + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + 3);
            AbstractSyntax = new SyntaxId(buffer, offset + 4);
            offset += 4 + SyntaxId.Length;
            for (var index = 0; index < numberOfTransferSyntaxItems; index++)
            {
                var syntax = new SyntaxId(buffer, offset);
                TransferSyntaxList.Add(syntax);
                offset += SyntaxId.Length;
            }
        }

        public int Length => 4 + SyntaxId.Length * (TransferSyntaxList.Count + 1);

        public void WriteBytes(byte[] buffer, int offset)
        {
            var numberOfTransferSyntaxItems = (byte) TransferSyntaxList.Count;

            LittleEndianWriter.WriteUInt16(buffer, offset + 0, ContextId);
            ByteWriter.WriteByte(buffer, offset + 2, numberOfTransferSyntaxItems);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            AbstractSyntax.WriteBytes(buffer, offset + 4);
            offset += 4 + SyntaxId.Length;

            for (var index = 0; index < numberOfTransferSyntaxItems; index++)
            {
                TransferSyntaxList[index].WriteBytes(buffer, offset);
                offset += SyntaxId.Length;
            }
        }
    }
}