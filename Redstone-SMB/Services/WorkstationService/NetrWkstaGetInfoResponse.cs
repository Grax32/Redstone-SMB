/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Enums;
using SMBLibrary.RPC.NDR;
using SMBLibrary.Services.WorkstationService.Structures;

namespace SMBLibrary.Services.WorkstationService
{
    public class NetrWkstaGetInfoResponse
    {
        public Win32Error Result;
        public WorkstationInfo WkstaInfo;

        public NetrWkstaGetInfoResponse()
        {
        }

        public NetrWkstaGetInfoResponse(byte[] buffer)
        {
            var parser = new NDRParser(buffer);
            WkstaInfo = new WorkstationInfo(parser);
            // 14.4 - If an operation returns a result, the representation of the result appears after all parameters in
            Result = (Win32Error) parser.ReadUInt32();
        }

        public byte[] GetBytes()
        {
            var writer = new NDRWriter();
            writer.WriteStructure(WkstaInfo);
            writer.WriteUInt32((uint) Result);

            return writer.GetBytes();
        }
    }
}