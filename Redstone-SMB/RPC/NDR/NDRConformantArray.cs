/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace RedstoneSmb.RPC.NDR
{
    public class NdrConformantArray<T> : List<T>, INdrStructure where T : INdrStructure, new()
    {
        /// <summary>
        ///     See DCE 1.1: Remote Procedure Call - 14.3.3.2 - Uni-dimensional Conformant Arrays
        /// </summary>
        /// <param name="parser"></param>
        public void Read(NdrParser parser)
        {
            parser.BeginStructure();
            var maxCount = parser.ReadUInt32();
            for (var index = 0; index < maxCount; index++)
            {
                var entry = new T();
                entry.Read(parser);
                Add(entry);
            }

            parser.EndStructure();
        }

        public void Write(NdrWriter writer)
        {
            writer.BeginStructure();
            var maxCount = (uint) Count;
            writer.WriteUInt32(maxCount);
            for (var index = 0; index < Count; index++) this[index].Write(writer);
            writer.EndStructure();
        }
    }
}