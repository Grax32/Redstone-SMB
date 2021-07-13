/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using RedstoneSmb.NTFileStore.Enums.FileInformation;

namespace RedstoneSmb.NTFileStore.Structures.FileInformation.Query
{
    /// <summary>
    ///     [MS-FSCC] 2.4.15 - FileFullEaInformation
    /// </summary>
    public class FileFullEaInformation : FileInformation
    {
        public FileFullEaInformation()
        {
        }

        public FileFullEaInformation(byte[] buffer, int offset)
        {
            Entries = ReadList(buffer, offset);
        }

        public List<FileFullEaEntry> Entries { get; } = new List<FileFullEaEntry>();

        public override FileInformationClass FileInformationClass => FileInformationClass.FileFullEaInformation;

        public override int Length
        {
            get
            {
                var length = 0;
                for (var index = 0; index < Entries.Count; index++)
                {
                    length += Entries[index].Length;
                    if (index < Entries.Count - 1)
                    {
                        // When multiple FILE_FULL_EA_INFORMATION data elements are present in the buffer, each MUST be aligned on a 4-byte boundary
                        var padding = (4 - length % 4) % 4;
                        length += padding;
                    }
                }

                return length;
            }
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            WriteList(buffer, offset, Entries);
        }

        public static List<FileFullEaEntry> ReadList(byte[] buffer, int offset)
        {
            var result = new List<FileFullEaEntry>();
            if (offset < buffer.Length)
            {
                FileFullEaEntry entry;
                do
                {
                    entry = new FileFullEaEntry(buffer, offset);
                    result.Add(entry);
                    offset += (int) entry.NextEntryOffset;
                } while (entry.NextEntryOffset != 0);
            }

            return result;
        }

        public static void WriteList(byte[] buffer, int offset, List<FileFullEaEntry> list)
        {
            for (var index = 0; index < list.Count; index++)
            {
                var entry = list[index];
                entry.WriteBytes(buffer, offset);
                var entryLength = entry.Length;
                offset += entryLength;
                if (index < list.Count - 1)
                {
                    // When multiple FILE_FULL_EA_INFORMATION data elements are present in the buffer, each MUST be aligned on a 4-byte boundary
                    var padding = (4 - entryLength % 4) % 4;
                    offset += padding;
                }
            }
        }
    }
}