/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;
using RedstoneSmb.Services.ServerService.Structures.ShareInfo;

namespace RedstoneSmb.Services.ServerService
{
    /// <summary>
    ///     NetrShareEnum Request (opnum 15)
    /// </summary>
    public class NetrShareEnumRequest
    {
        public ShareEnum InfoStruct;
        public uint PreferedMaximumLength; // Preferred maximum length, in bytes, of the returned data
        public uint ResumeHandle;
        public string ServerName;

        public NetrShareEnumRequest()
        {
        }

        public NetrShareEnumRequest(byte[] buffer)
        {
            var parser = new NdrParser(buffer);
            ServerName = parser.ReadTopLevelUnicodeStringPointer();
            InfoStruct = new ShareEnum(parser);
            PreferedMaximumLength = parser.ReadUInt32();
            ResumeHandle = parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            var writer = new NdrWriter();
            writer.WriteTopLevelUnicodeStringPointer(ServerName);
            writer.WriteStructure(InfoStruct);
            writer.WriteUInt32(PreferedMaximumLength);
            writer.WriteUInt32(ResumeHandle);

            return writer.GetBytes();
        }
    }
}