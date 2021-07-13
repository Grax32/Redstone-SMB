/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.Enums;
using RedstoneSmb.RPC.NDR;
using RedstoneSmb.Services.ServerService.Structures.ShareInfo;

namespace RedstoneSmb.Services.ServerService
{
    /// <summary>
    ///     NetrShareGetInfo Response (opnum 16)
    /// </summary>
    public class NetrShareGetInfoResponse
    {
        public ShareInfo InfoStruct;
        public Win32Error Result;

        public NetrShareGetInfoResponse()
        {
        }

        public NetrShareGetInfoResponse(byte[] buffer)
        {
            var parser = new NdrParser(buffer);
            InfoStruct = new ShareInfo(parser);
            Result = (Win32Error) parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            var writer = new NdrWriter();
            writer.WriteStructure(InfoStruct);
            writer.WriteUInt32((uint) Result);

            return writer.GetBytes();
        }
    }
}