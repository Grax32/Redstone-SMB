/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;

namespace RedstoneSmb.Services.ServerService
{
    /// <summary>
    ///     NetrShareGetInfo Request (opnum 16)
    /// </summary>
    public class NetrShareGetInfoRequest
    {
        public uint Level;
        public string NetName; // Share name
        public string ServerName;

        public NetrShareGetInfoRequest(byte[] buffer)
        {
            var parser = new NdrParser(buffer);
            ServerName = parser.ReadTopLevelUnicodeStringPointer();
            NetName = parser.ReadUnicodeString();
            Level = parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            var writer = new NdrWriter();
            writer.WriteTopLevelUnicodeStringPointer(ServerName);
            writer.WriteUnicodeString(NetName);
            writer.WriteUInt32(Level);

            return writer.GetBytes();
        }
    }
}