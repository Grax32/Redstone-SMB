/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using SMBLibrary.Utilities.ByteUtils;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;

namespace SMBLibrary.Authentication.GSSAPI.SPNEGO
{
    /// <summary>
    ///     RFC 4178 - negTokenInit
    /// </summary>
    public class SimpleProtectedNegotiationTokenInit : SimpleProtectedNegotiationToken
    {
        public const byte NegTokenInitTag = 0xA0;
        public const byte MechanismTypeListTag = 0xA0;
        public const byte RequiredFlagsTag = 0xA1;
        public const byte MechanismTokenTag = 0xA2;
        public const byte MechanismListMICTag = 0xA3;

        public byte[] MechanismListMIC; // Optional

        // reqFlags - Optional, RECOMMENDED to be left out
        public byte[] MechanismToken; // Optional

        /// <summary>
        ///     Contains one or more security mechanisms available for the initiator, in decreasing preference order.
        /// </summary>
        public List<byte[]> MechanismTypeList; // Optional

        public SimpleProtectedNegotiationTokenInit()
        {
        }

        /// <param name="offset">The offset following the NegTokenInit tag</param>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SimpleProtectedNegotiationTokenInit(byte[] buffer, int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.Sequence) throw new InvalidDataException();
            var sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == MechanismTypeListTag)
                    MechanismTypeList = ReadMechanismTypeList(buffer, ref offset);
                else if (tag == RequiredFlagsTag)
                    throw new NotImplementedException("negTokenInit.ReqFlags is not implemented");
                else if (tag == MechanismTokenTag)
                    MechanismToken = ReadMechanismToken(buffer, ref offset);
                else if (tag == MechanismListMICTag)
                    MechanismListMIC = ReadMechanismListMIC(buffer, ref offset);
                else
                    throw new InvalidDataException("Invalid negTokenInit structure");
            }
        }

        public override byte[] GetBytes()
        {
            var sequenceLength = GetTokenFieldsLength();
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
            var bufferSize = 1 + constructionLengthFieldSize + 1 + sequenceLengthFieldSize + sequenceLength;
            var buffer = new byte[bufferSize];
            var offset = 0;
            ByteWriter.WriteByte(buffer, ref offset, NegTokenInitTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            if (MechanismTypeList != null) WriteMechanismTypeList(buffer, ref offset, MechanismTypeList);
            if (MechanismToken != null) WriteMechanismToken(buffer, ref offset, MechanismToken);
            if (MechanismListMIC != null) WriteMechanismListMIC(buffer, ref offset, MechanismListMIC);
            return buffer;
        }

        protected virtual int GetTokenFieldsLength()
        {
            var result = 0;
            if (MechanismTypeList != null)
            {
                var typeListSequenceLength = GetMechanismTypeListSequenceLength(MechanismTypeList);
                var typeListSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(typeListSequenceLength);
                var typeListConstructionLength = 1 + typeListSequenceLengthFieldSize + typeListSequenceLength;
                var typeListConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(typeListConstructionLength);
                var entryLength = 1 + typeListConstructionLengthFieldSize + 1 + typeListSequenceLengthFieldSize +
                                  typeListSequenceLength;
                result += entryLength;
            }

            if (MechanismToken != null)
            {
                var mechanismTokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismToken.Length);
                var mechanismTokenConstructionLength = 1 + mechanismTokenLengthFieldSize + MechanismToken.Length;
                var mechanismTokenConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(mechanismTokenConstructionLength);
                var entryLength = 1 + mechanismTokenConstructionLengthFieldSize + 1 + mechanismTokenLengthFieldSize +
                                  MechanismToken.Length;
                ;
                result += entryLength;
            }

            if (MechanismListMIC != null)
            {
                var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismListMIC.Length);
                var mechanismListMICConstructionLength = 1 + mechanismListMICLengthFieldSize + MechanismListMIC.Length;
                var mechanismListMICConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(mechanismListMICConstructionLength);
                var entryLength = 1 + mechanismListMICConstructionLengthFieldSize + 1 +
                                  mechanismListMICLengthFieldSize + MechanismListMIC.Length;
                result += entryLength;
            }

            return result;
        }

        protected static List<byte[]> ReadMechanismTypeList(byte[] buffer, ref int offset)
        {
            var result = new List<byte[]>();
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.Sequence) throw new InvalidDataException();
            var sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag != (byte) DerEncodingTag.ObjectIdentifier) throw new InvalidDataException();
                var mechanismTypeLength = DerEncodingHelper.ReadLength(buffer, ref offset);
                var mechanismType = ByteReader.ReadBytes(buffer, ref offset, mechanismTypeLength);
                result.Add(mechanismType);
            }

            return result;
        }

        protected static byte[] ReadMechanismToken(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.ByteArray) throw new InvalidDataException();
            var mechanismTokenLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var token = ByteReader.ReadBytes(buffer, ref offset, mechanismTokenLength);
            return token;
        }

        protected static byte[] ReadMechanismListMIC(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.ByteArray) throw new InvalidDataException();
            var length = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes(buffer, ref offset, length);
        }

        protected static int GetMechanismTypeListSequenceLength(List<byte[]> mechanismTypeList)
        {
            var sequenceLength = 0;
            foreach (var mechanismType in mechanismTypeList)
            {
                var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismType.Length);
                var entryLength = 1 + lengthFieldSize + mechanismType.Length;
                sequenceLength += entryLength;
            }

            return sequenceLength;
        }

        protected static void WriteMechanismTypeList(byte[] buffer, ref int offset, List<byte[]> mechanismTypeList)
        {
            var sequenceLength = GetMechanismTypeListSequenceLength(mechanismTypeList);
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            ByteWriter.WriteByte(buffer, ref offset, MechanismTypeListTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            foreach (var mechanismType in mechanismTypeList)
            {
                ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ObjectIdentifier);
                DerEncodingHelper.WriteLength(buffer, ref offset, mechanismType.Length);
                ByteWriter.WriteBytes(buffer, ref offset, mechanismType);
            }
        }

        protected static void WriteMechanismToken(byte[] buffer, ref int offset, byte[] mechanismToken)
        {
            var constructionLength =
                1 + DerEncodingHelper.GetLengthFieldSize(mechanismToken.Length) + mechanismToken.Length;
            ByteWriter.WriteByte(buffer, ref offset, MechanismTokenTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, mechanismToken.Length);
            ByteWriter.WriteBytes(buffer, ref offset, mechanismToken);
        }

        protected static void WriteMechanismListMIC(byte[] buffer, ref int offset, byte[] mechanismListMIC)
        {
            var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
            ByteWriter.WriteByte(buffer, ref offset, MechanismListMICTag);
            DerEncodingHelper.WriteLength(buffer, ref offset,
                1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, mechanismListMIC.Length);
            ByteWriter.WriteBytes(buffer, ref offset, mechanismListMIC);
        }
    }
}