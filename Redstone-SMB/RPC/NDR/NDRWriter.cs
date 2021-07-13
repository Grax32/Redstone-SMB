/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.IO;
using ByteWriter = RedstoneSmb.Utilities.ByteUtils.ByteWriter;
using LittleEndianWriter = RedstoneSmb.Utilities.ByteUtils.LittleEndianWriter;

namespace RedstoneSmb.RPC.NDR
{
    /// <summary>
    ///     NDR - Native Data Representation
    ///     See DCE 1.1: Remote Procedure Call, Chapter 14 - Transfer Syntax NDR
    /// </summary>
    public class NdrWriter
    {
        private readonly List<INdrStructure> _mDeferredStructures = new List<INdrStructure>();
        private int _mDepth;
        private uint _mNextReferentId = 0x00020000;
        private readonly Dictionary<uint, INdrStructure> _mReferentToInstance = new Dictionary<uint, INdrStructure>();
        private readonly MemoryStream _mStream = new MemoryStream();

        public void BeginStructure()
        {
            _mDepth++;
        }

        /// <summary>
        ///     Add embedded pointer deferred structure (referent) writer
        /// </summary>
        private void AddDeferredStructure(INdrStructure structure)
        {
            _mDeferredStructures.Add(structure);
        }

        public void EndStructure()
        {
            _mDepth--;
            // 14.3.12.3 - Algorithm for Deferral of Referents
            // Representations of (embedded) pointer referents are ordered according to a left-to-right, depth-first traversal of the embedding construction.
            // referent representations for the embedded construction are further deferred to a position in the octet stream that
            // follows the representation of the embedding construction. The set of referent representations for the embedded construction
            // is inserted among the referent representations for any pointers in the embedding construction, according to the order of elements or
            // members in the embedding construction
            if (_mDepth == 0)
            {
                // Make a copy of all the deferred structures, additional deferred structures will be inserted to m_deferredStructures
                // as we process the existing list
                var deferredStructures = new List<INdrStructure>(_mDeferredStructures);
                _mDeferredStructures.Clear();
                // Write all deferred types:
                foreach (var deferredStructure in deferredStructures) deferredStructure.Write(this);
            }
        }

        public void WriteUnicodeString(string value)
        {
            var unicodeString = new NdrUnicodeString(value);
            unicodeString.Write(this);
        }

        public void WriteStructure(INdrStructure structure)
        {
            structure.Write(this);
        }

        public void WriteTopLevelUnicodeStringPointer(string value)
        {
            if (value == null)
            {
                WriteUInt32(0);
                return;
            }

            // Note: We do not bother searching for existing values
            var referentId = GetNextReferentId();
            WriteUInt32(referentId);
            var unicodeString = new NdrUnicodeString(value);
            unicodeString.Write(this);
            _mReferentToInstance.Add(referentId, unicodeString);
        }

        // 14.3.12.1 Embedded Full Pointers
        public void WriteEmbeddedStructureFullPointer(INdrStructure structure)
        {
            if (structure == null)
            {
                WriteUInt32(0); // null
            }
            else
            {
                // Note: We do not bother searching for existing values
                var referentId = GetNextReferentId();
                WriteUInt32(referentId);
                AddDeferredStructure(structure);
                _mReferentToInstance.Add(referentId, structure);
            }
        }

        // 14.2.2 - Alignment of Primitive Types
        public void WriteUInt16(ushort value)
        {
            var padding = (uint) (2 - _mStream.Position % 2) % 2;
            _mStream.Position += padding;
            LittleEndianWriter.WriteUInt16(_mStream, value);
        }

        // 14.2.2 - Alignment of Primitive Types
        public void WriteUInt32(uint value)
        {
            var padding = (uint) (4 - _mStream.Position % 4) % 4;
            _mStream.Position += padding;
            LittleEndianWriter.WriteUInt32(_mStream, value);
        }

        public void WriteBytes(byte[] value)
        {
            ByteWriter.WriteBytes(_mStream, value);
        }

        public byte[] GetBytes()
        {
            var buffer = new byte[_mStream.Length];
            _mStream.Seek(0, SeekOrigin.Begin);
            _mStream.Read(buffer, 0, buffer.Length);
            return buffer;
        }

        private uint GetNextReferentId()
        {
            var result = _mNextReferentId;
            _mNextReferentId++;
            return result;
        }
    }
}