/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;

namespace RedstoneSmb.Services.ServerService
{
    /// <summary>
    ///     NetrServerGetInfo Request (opnum 21)
    /// </summary>
    public class NetrServerGetInfoRequest
    {
        public uint Level;
        public string ServerName;

        public NetrServerGetInfoRequest()
        {
        }

        public NetrServerGetInfoRequest(byte[] buffer)
        {
            var parser = new NdrParser(buffer);
            ServerName = parser.ReadTopLevelUnicodeStringPointer();
            Level = parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            var writer = new NdrWriter();
            writer.WriteTopLevelUnicodeStringPointer(ServerName);
            writer.WriteUInt32(Level);

            return writer.GetBytes();
        }
    }
}