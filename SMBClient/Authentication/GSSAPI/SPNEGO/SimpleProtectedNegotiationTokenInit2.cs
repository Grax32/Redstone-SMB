/* Copyright (C) 2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using SMBLibrary.Utilities.ByteUtils;
using ByteReader = SMBLibrary.Utilities.ByteUtils.ByteReader;
using ByteWriter = SMBLibrary.Utilities.ByteUtils.ByteWriter;

namespace SMBLibrary.Authentication.GSSAPI.SPNEGO
{
    /// <summary>
    ///     [MS-SPNG] - NegTokenInit2
    /// </summary>
    public class SimpleProtectedNegotiationTokenInit2 : SimpleProtectedNegotiationTokenInit
    {
        public const byte NegHintsTag = 0xA3;
        public new const byte MechanismListMICTag = 0xA4;

        public const byte HintNameTag = 0xA0;
        public const byte HintAddressTag = 0xA1;
        public byte[] HintAddress;

        public string HintName;

        public SimpleProtectedNegotiationTokenInit2()
        {
            HintName = "not_defined_in_RFC4178@please_ignore";
        }

        /// <param name="offset">The offset following the NegTokenInit2 tag</param>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SimpleProtectedNegotiationTokenInit2(byte[] buffer, int offset)
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
                else if (tag == NegHintsTag)
                    HintName = ReadHints(buffer, ref offset, out HintAddress);
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
            if (HintName != null || HintAddress != null) WriteHints(buffer, ref offset, HintName, HintAddress);
            if (MechanismListMIC != null) WriteMechanismListMIC(buffer, ref offset, MechanismListMIC);
            return buffer;
        }

        protected override int GetTokenFieldsLength()
        {
            var result = base.GetTokenFieldsLength();
            ;
            if (HintName != null || HintAddress != null)
            {
                var hintsSequenceLength = GetHintsSequenceLength(HintName, HintAddress);
                var hintsSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintsSequenceLength);
                var hintsSequenceConstructionLength = 1 + hintsSequenceLengthFieldSize + hintsSequenceLength;
                var hintsSequenceConstructionLengthFieldSize =
                    DerEncodingHelper.GetLengthFieldSize(hintsSequenceConstructionLength);
                var entryLength = 1 + hintsSequenceConstructionLengthFieldSize + 1 + hintsSequenceLengthFieldSize +
                                  hintsSequenceLength;
                result += entryLength;
            }

            return result;
        }

        protected static string ReadHints(byte[] buffer, ref int offset, out byte[] hintAddress)
        {
            string hintName = null;
            hintAddress = null;
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.Sequence) throw new InvalidDataException();
            var sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == HintNameTag)
                    hintName = ReadHintName(buffer, ref offset);
                else if (tag == HintAddressTag)
                    hintAddress = ReadHintAddress(buffer, ref offset);
                else
                    throw new InvalidDataException();
            }

            return hintName;
        }

        protected static string ReadHintName(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.GeneralString) throw new InvalidDataException();
            var hintLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var hintNameBytes = ByteReader.ReadBytes(buffer, ref offset, hintLength);
            return DerEncodingHelper.DecodeGeneralString(hintNameBytes);
        }

        protected static byte[] ReadHintAddress(byte[] buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte) DerEncodingTag.ByteArray) throw new InvalidDataException();
            var hintLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes(buffer, ref offset, hintLength);
        }

        protected static int GetHintsSequenceLength(string hintName, byte[] hintAddress)
        {
            var sequenceLength = 0;
            if (hintName != null)
            {
                var hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
                var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length);
                var constructionLength = 1 + lengthFieldSize + hintNameBytes.Length;
                var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
                var entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintNameBytes.Length;
                sequenceLength += entryLength;
            }

            if (hintAddress != null)
            {
                var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintAddress.Length);
                var constructionLength = 1 + lengthFieldSize + hintAddress.Length;
                var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
                var entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintAddress.Length;
                sequenceLength += entryLength;
            }

            return sequenceLength;
        }

        private static void WriteHints(byte[] buffer, ref int offset, string hintName, byte[] hintAddress)
        {
            var sequenceLength = GetHintsSequenceLength(hintName, hintAddress);
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            ByteWriter.WriteByte(buffer, ref offset, NegHintsTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            if (hintName != null) WriteHintName(buffer, ref offset, hintName);
            if (hintAddress != null) WriteHintAddress(buffer, ref offset, hintAddress);
        }

        private static void WriteHintName(byte[] buffer, ref int offset, string hintName)
        {
            var hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
            var constructionLength =
                1 + DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length) + hintNameBytes.Length;
            ByteWriter.WriteByte(buffer, ref offset, HintNameTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.GeneralString);
            DerEncodingHelper.WriteLength(buffer, ref offset, hintNameBytes.Length);
            ByteWriter.WriteBytes(buffer, ref offset, hintNameBytes);
        }

        private static void WriteHintAddress(byte[] buffer, ref int offset, byte[] hintAddress)
        {
            var constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintAddress.Length) + hintAddress.Length;
            ByteWriter.WriteByte(buffer, ref offset, HintAddressTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            ByteWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, hintAddress.Length);
            ByteWriter.WriteBytes(buffer, ref offset, hintAddress);
        }

        protected new static void WriteMechanismListMIC(byte[] buffer, ref int offset, byte[] mechanismListMIC)
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