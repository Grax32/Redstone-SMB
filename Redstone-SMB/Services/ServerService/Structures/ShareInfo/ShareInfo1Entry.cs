/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;
using RedstoneSmb.Services.ServerService.EnumStructures;

namespace RedstoneSmb.Services.ServerService.Structures.ShareInfo
{
    /// <summary>
    ///     [MS-SRVS] SHARE_INFO_1
    /// </summary>
    public class ShareInfo1Entry : IShareInfoEntry
    {
        public NdrUnicodeString NetName;
        public NdrUnicodeString Remark;
        public ShareTypeExtended ShareType;

        public ShareInfo1Entry()
        {
        }

        public ShareInfo1Entry(string shareName, ShareTypeExtended shareType)
        {
            NetName = new NdrUnicodeString(shareName);
            ShareType = shareType;
            Remark = new NdrUnicodeString(string.Empty);
        }

        public ShareInfo1Entry(NdrParser parser)
        {
            Read(parser);
        }

        public void Read(NdrParser parser)
        {
            parser.BeginStructure();
            parser.ReadEmbeddedStructureFullPointer(ref NetName);
            ShareType = new ShareTypeExtended(parser);
            parser.ReadEmbeddedStructureFullPointer(ref Remark);
            parser.EndStructure();
        }

        public void Write(NdrWriter writer)
        {
            writer.BeginStructure();
            writer.WriteEmbeddedStructureFullPointer(NetName);
            ShareType.Write(writer);
            writer.WriteEmbeddedStructureFullPointer(Remark);
            writer.EndStructure();
        }

        public uint Level => 1;
    }
}