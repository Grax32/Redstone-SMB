/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;
using LittleEndianReader = RedstoneSmb.Utilities.ByteUtils.LittleEndianReader;

namespace RedstoneSmb.RPC.NDR
{
    /// <summary>
    ///     NDR - Native Data Representation
    ///     See DCE 1.1: Remote Procedure Call, Chapter 14 - Transfer Syntax NDR
    /// </summary>
    public class NdrParser
    {
        private readonly byte[] _mBuffer;
        private readonly List<INdrStructure> _mDeferredStructures = new List<INdrStructure>();
        private int _mDepth;
        private int _mOffset;
        private readonly Dictionary<uint, INdrStructure> _mReferentToInstance = new Dictionary<uint, INdrStructure>();

        public NdrParser(byte[] buffer)
        {
            _mBuffer = buffer;
            _mOffset = 0;
            _mDepth = 0;
        }

        public void BeginStructure()
        {
            _mDepth++;
        }

        /// <summary>
        ///     Add embedded pointer deferred structure (referent) parser
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
                // Read all deferred types:
                foreach (var deferredStructure in deferredStructures) deferredStructure.Read(this);
            }
        }

        public string ReadUnicodeString()
        {
            var unicodeString = new NdrUnicodeString(this);
            return unicodeString.Value;
        }

        public void ReadStructure(INdrStructure structure)
        {
            structure.Read(this);
        }

        // 14.3.11.1 - Top-level Full Pointers
        public string ReadTopLevelUnicodeStringPointer()
        {
            var referentId = ReadUInt32();
            if (referentId == 0) return null;

            if (_mReferentToInstance.ContainsKey(referentId))
            {
                var unicodeString = (NdrUnicodeString) _mReferentToInstance[referentId];
                return unicodeString.Value;
            }
            else
            {
                var unicodeString = new NdrUnicodeString(this);
                _mReferentToInstance.Add(referentId, unicodeString);
                return unicodeString.Value;
            }
        }

        public void ReadEmbeddedStructureFullPointer(ref NdrUnicodeString structure)
        {
            ReadEmbeddedStructureFullPointer<NdrUnicodeString>(ref structure);
        }

        public void ReadEmbeddedStructureFullPointer<T>(ref T structure) where T : INdrStructure, new()
        {
            var referentId = ReadUInt32();
            if (referentId != 0) // not null
            {
                if (structure == null) structure = new T();
                AddDeferredStructure(structure);
            }
            else
            {
                structure = default;
            }
        }

        // 14.2.2 - Alignment of Primitive Types
        public uint ReadUInt16()
        {
            _mOffset += (2 - _mOffset % 2) % 2;
            return LittleEndianReader.ReadUInt16(_mBuffer, ref _mOffset);
        }

        // 14.2.2 - Alignment of Primitive Types
        public uint ReadUInt32()
        {
            _mOffset += (4 - _mOffset % 4) % 4;
            return LittleEndianReader.ReadUInt32(_mBuffer, ref _mOffset);
        }

        public byte[] ReadBytes(int count)
        {
            return ByteReader.ReadBytes(_mBuffer, ref _mOffset, count);
        }
    }
}