/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;

namespace RedstoneSmb.NTFileStore
{
    public class FileHandle
    {
        public bool DeleteOnClose;
        public bool IsDirectory;
        public string Path;
        public Stream Stream;

        public FileHandle(string path, bool isDirectory, Stream stream, bool deleteOnClose)
        {
            Path = path;
            IsDirectory = isDirectory;
            Stream = stream;
            DeleteOnClose = deleteOnClose;
        }
    }
}