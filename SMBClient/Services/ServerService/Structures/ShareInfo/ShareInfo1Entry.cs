/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC.NDR;
using SMBLibrary.Services.ServerService.EnumStructures;

namespace SMBLibrary.Services.ServerService.Structures.ShareInfo
{
    /// <summary>
    ///     [MS-SRVS] SHARE_INFO_1
    /// </summary>
    public class ShareInfo1Entry : IShareInfoEntry
    {
        public NDRUnicodeString NetName;
        public NDRUnicodeString Remark;
        public ShareTypeExtended ShareType;

        public ShareInfo1Entry()
        {
        }

        public ShareInfo1Entry(string shareName, ShareTypeExtended shareType)
        {
            NetName = new NDRUnicodeString(shareName);
            ShareType = shareType;
            Remark = new NDRUnicodeString(string.Empty);
        }

        public ShareInfo1Entry(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            parser.ReadEmbeddedStructureFullPointer(ref NetName);
            ShareType = new ShareTypeExtended(parser);
            parser.ReadEmbeddedStructureFullPointer(ref Remark);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
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