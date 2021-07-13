/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;

namespace RedstoneSmb.Services.WorkstationService.Structures
{
    public abstract class WorkstationInfoLevel : INdrStructure
    {
        public abstract uint Level { get; }

        public abstract void Read(NdrParser parser);

        public abstract void Write(NdrWriter writer);
    }
}