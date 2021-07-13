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
    ///     [MS-SRVS] SHARE_INFO_0
    /// </summary>
    public class ShareInfo0Entry : IShareInfoEntry
    {
        public NdrUnicodeString NetName;

        public ShareInfo0Entry()
        {
        }

        public ShareInfo0Entry(string shareName)
        {
            NetName = new NdrUnicodeString(shareName);
        }

        public ShareInfo0Entry(NdrParser parser)
        {
            Read(parser);
        }

        public void Read(NdrParser parser)
        {
            parser.BeginStructure();
            parser.ReadEmbeddedStructureFullPointer(ref NetName);
            parser.EndStructure();
        }

        public void Write(NdrWriter writer)
        {
            writer.BeginStructure();
            writer.WriteEmbeddedStructureFullPointer(NetName);
            writer.EndStructure();
        }

        public uint Level => 0;
    }
}