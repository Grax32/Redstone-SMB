/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;
using RedstoneSmb.Services.Enums;

namespace RedstoneSmb.Services.ServerService.Structures.ServerInfo
{
    /// <summary>
    ///     [MS-SRVS] SERVER_INFO_100
    /// </summary>
    public class ServerInfo100 : ServerInfoLevel
    {
        public PlatformName PlatformId;
        public NdrUnicodeString ServerName;

        public ServerInfo100()
        {
            ServerName = new NdrUnicodeString();
        }

        public ServerInfo100(NdrParser parser)
        {
            Read(parser);
        }

        public override uint Level => 100;

        public override void Read(NdrParser parser)
        {
            // If an array, structure, or union embeds a pointer, the representation of the referent of the
            // pointer is deferred to a position in the octet stream that follows the representation of the
            // embedding construction
            parser.BeginStructure();
            PlatformId = (PlatformName) parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref ServerName);
            parser.EndStructure();
        }

        public override void Write(NdrWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint) PlatformId);
            writer.WriteEmbeddedStructureFullPointer(ServerName);
            writer.EndStructure();
        }
    }
}