/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;

namespace RedstoneSmb.Services.ServerService.Structures.ShareInfo
{
    /// <summary>
    ///     [MS-SRVS] SHARE_INFO_1_CONTAINER
    /// </summary>
    public class ShareInfo1Container : IShareInfoContainer
    {
        public NdrConformantArray<ShareInfo1Entry> Entries;

        public ShareInfo1Container()
        {
        }

        public ShareInfo1Container(NdrParser parser)
        {
            Read(parser);
        }

        public int Count
        {
            get
            {
                if (Entries != null)
                    return Entries.Count;
                return 0;
            }
        }

        public void Read(NdrParser parser)
        {
            parser.BeginStructure();
            var count = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref Entries);
            parser.EndStructure();
        }

        public void Write(NdrWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint) Count);
            writer.WriteEmbeddedStructureFullPointer(Entries);
            writer.EndStructure();
        }

        public uint Level => 1;

        public void Add(ShareInfo1Entry entry)
        {
            if (Entries == null) Entries = new NdrConformantArray<ShareInfo1Entry>();
            Entries.Add(entry);
        }
    }
}