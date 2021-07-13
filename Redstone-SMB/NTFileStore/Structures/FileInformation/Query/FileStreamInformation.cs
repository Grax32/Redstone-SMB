/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    ///     [MS-FSCC] 2.4.40 - FileStreamInformation
    /// </summary>
    public class FileStreamInformation : FileInformation
    {
        public FileStreamInformation()
        {
        }

        public FileStreamInformation(byte[] buffer, int offset)
        {
            if (offset < buffer.Length)
            {
                FileStreamEntry entry;
                do
                {
                    entry = new FileStreamEntry(buffer, offset);
                    Entries.Add(entry);
                    offset += (int) entry.NextEntryOffset;
                } while (entry.NextEntryOffset != 0);
            }
        }

        public List<FileStreamEntry> Entries { get; } = new List<FileStreamEntry>();

        public override FileInformationClass FileInformationClass => FileInformationClass.FileStreamInformation;

        public override int Length
        {
            get
            {
                var length = 0;
                for (var index = 0; index < Entries.Count; index++)
                {
                    var entry = Entries[index];
                    var entryLength = index < Entries.Count - 1 ? entry.PaddedLength : entry.Length;
                    length += entryLength;
                }

                return length;
            }
        }

        public override void WriteBytes(byte[] buffer, int offset)
        {
            for (var index = 0; index < Entries.Count; index++)
            {
                var entry = Entries[index];
                var entryLength = entry.PaddedLength;
                entry.NextEntryOffset = index < Entries.Count - 1 ? (uint) entryLength : 0;
                entry.WriteBytes(buffer, offset);
                offset += entryLength;
            }
        }
    }
}