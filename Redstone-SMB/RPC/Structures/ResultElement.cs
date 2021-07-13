/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.Enums;
using LittleEndianConverter = RedstoneSmb.Utilities.Conversion.LittleEndianConverter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.Structures
{
    /// <summary>
    ///     p_result_t
    /// </summary>
    public struct ResultElement
    {
        public const int Length = 24;

        public NegotiationResult Result;
        public RejectionReason Reason;
        public SyntaxId TransferSyntax;

        public ResultElement(byte[] buffer, int offset)
        {
            Result = (NegotiationResult) LittleEndianConverter.ToUInt16(buffer, offset + 0);
            Reason = (RejectionReason) LittleEndianConverter.ToUInt16(buffer, offset + 2);
            TransferSyntax = new SyntaxId(buffer, offset + 4);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, (ushort) Result);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort) Reason);
            TransferSyntax.WriteBytes(buffer, offset + 4);
        }
    }
}