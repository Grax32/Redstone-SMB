/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RedstoneSmb.Services.ServerService;
using RedstoneSmb.Services.WorkstationService;
using Utilities;

namespace SMBLibrary.Tests
{
    [TestClass]
    public class RpcTests
    {
        [TestMethod]
        public void Test1()
        {
            byte[] buffer = new byte[]{ 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xf4, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
                                        0x08, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x54, 0x00, 0x41, 0x00, 0x4c, 0x00, 0x32, 0x00,
                                        0x2d, 0x00, 0x56, 0x00, 0x4d, 0x00, 0x37, 0x00, 0x00, 0x00, 0xcd, 0xab, 0x0a, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00,
                                        0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            NetrWkstaGetInfoResponse response = new NetrWkstaGetInfoResponse(buffer);

            byte[] responseBytes = response.GetBytes();
            //Assert.IsTrue(ByteUtils.AreByteArraysEqual(buffer, responseBytes));
        }

        [TestMethod]
        public void Test2()
        {
            byte[] buffer = new byte[] { 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xf4, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x90, 0x84, 0x00, 0x08, 0x00, 0x02, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x35, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00 };
            NetrServerGetInfoResponse response = new NetrServerGetInfoResponse(buffer);

            byte[] responseBytes = response.GetBytes();
            //Assert.IsTrue(ByteUtils.AreByteArraysEqual(buffer, responseBytes));
        }

        [TestMethod]
        public void Test3()
        {
            byte[] buffer = new byte[] {0x00, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
                                        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00,
                                        0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x35, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00};
            NetrShareEnumRequest request = new NetrShareEnumRequest(buffer);

            byte[] requestBytes = request.GetBytes();
            //Assert.IsTrue(ByteUtils.AreByteArraysEqual(buffer, requestBytes));
        }

        [TestMethod]
        public void Test4()
        {
            byte[] buffer = new byte[] {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
                                        0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80,
                                        0x0c, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00,
                                        0x18, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x80, 0x1c, 0x00, 0x02, 0x00, 0x20, 0x00, 0x02, 0x00,
                                        0x00, 0x00, 0x00, 0x80, 0x24, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x03, 0x00, 0x00, 0x00, 0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0x69, 0x00, 0x0e, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x44, 0x00, 0x65, 0x00, 0x66, 0x00, 0x61, 0x00,
                                        0x75, 0x00, 0x6c, 0x00, 0x74, 0x00, 0x20, 0x00, 0x73, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00,
                                        0x65, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
                                        0x53, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00, 0x65, 0x00, 0x64, 0x00, 0x00, 0x00, 0x41, 0x00,
                                        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x49, 0x00, 0x50, 0x00,
                                        0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0x24, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x0b, 0x00, 0x00, 0x00, 0x52, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x65, 0x00,
                                        0x20, 0x00, 0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x00, 0x00, 0x68, 0x00, 0x07, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x41, 0x00, 0x44, 0x00, 0x4d, 0x00, 0x49, 0x00,
                                        0x4e, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x0d, 0x00, 0x00, 0x00, 0x52, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x65, 0x00,
                                        0x20, 0x00, 0x41, 0x00, 0x64, 0x00, 0x6d, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            NetrShareEnumResponse response = new NetrShareEnumResponse(buffer);

            byte[] responseBytes = response.GetBytes();
            //Assert.IsTrue(ByteUtils.AreByteArraysEqual(buffer, responseBytes));
        }

        [TestMethod]
        public void Test5()
        {
            byte[] buffer = new byte[] {0x00, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
                                        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x36, 0x00,
                                        0x38, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x35, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x53, 0x00, 0x68, 0x00,
                                        0x61, 0x00, 0x72, 0x00, 0x65, 0x00, 0x64, 0x00, 0x00, 0x00, 0xb7, 0x6c, 0x02, 0x00, 0x00, 0x00};
            NetrShareGetInfoRequest request = new NetrShareGetInfoRequest(buffer);

            byte[] requestBytes = request.GetBytes();
            //Assert.IsTrue(ByteUtils.AreByteArraysEqual(buffer, requestBytes));
        }

        public void TestAll()
        {
            Test1();
            Test2();
            Test3();
            Test4();
            Test5();
        }
    }
}
