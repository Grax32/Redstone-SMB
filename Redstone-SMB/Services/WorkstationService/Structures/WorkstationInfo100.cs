/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using RedstoneSmb.RPC.NDR;

namespace RedstoneSmb.Services.WorkstationService.Structures
{
    /// <summary>
    ///     [MS-WKST] WKSTA_INFO_100
    /// </summary>
    public class WorkstationInfo100 : WorkstationInfoLevel
    {
        public NdrUnicodeString ComputerName;
        public NdrUnicodeString LanGroup;
        public uint PlatformId;
        public uint VerMajor;
        public uint VerMinor;

        public WorkstationInfo100()
        {
            ComputerName = new NdrUnicodeString();
            LanGroup = new NdrUnicodeString();
        }

        public WorkstationInfo100(NdrParser parser)
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
            PlatformId = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref ComputerName);
            parser.ReadEmbeddedStructureFullPointer(ref LanGroup);
            VerMajor = parser.ReadUInt32();
            VerMinor = parser.ReadUInt32();
            parser.EndStructure();
        }

        public override void Write(NdrWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(PlatformId);
            writer.WriteEmbeddedStructureFullPointer(ComputerName);
            writer.WriteEmbeddedStructureFullPointer(LanGroup);
            writer.WriteUInt32(VerMajor);
            writer.WriteUInt32(VerMinor);
            writer.EndStructure();
        }
    }
}