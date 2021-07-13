/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using RedstoneSmb.Enums;
using RedstoneSmb.Services.Enums;
using RedstoneSmb.Services.Exceptions;
using RedstoneSmb.Services.ServerService.Enums;
using RedstoneSmb.Services.ServerService.EnumStructures;
using RedstoneSmb.Services.ServerService.Structures.ServerInfo;
using RedstoneSmb.Services.ServerService.Structures.ShareInfo;

namespace RedstoneSmb.Services.ServerService
{
    /// <summary>
    ///     [MS-SRVS]
    /// </summary>
    public class ServerService : RemoteService
    {
        public const string ServicePipeName = @"srvsvc";
        public const int ServiceVersion = 3;

        public const int MaxPreferredLength = -1; // MAX_PREFERRED_LENGTH
        public static readonly Guid ServiceInterfaceGuid = new Guid("4B324FC8-1670-01D3-1278-5A47BF6EE188");

        private readonly PlatformName _mPlatformId;
        private readonly string _mServerName;
        private readonly ServerType _mServerType;

        private readonly List<string> _mShares;
        private readonly uint _mVerMajor;
        private readonly uint _mVerMinor;

        public ServerService(string serverName, List<string> shares)
        {
            _mPlatformId = PlatformName.Nt;
            _mServerName = serverName;
            _mVerMajor = 5;
            _mVerMinor = 2;
            _mServerType = ServerType.Workstation | ServerType.Server | ServerType.WindowsNt | ServerType.ServerNt |
                           ServerType.MasterBrowser;

            _mShares = shares;
        }

        public override Guid InterfaceGuid => ServiceInterfaceGuid;

        public override string PipeName => ServicePipeName;

        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes)
        {
            switch ((ServerServiceOpName) opNum)
            {
                case ServerServiceOpName.NetrShareEnum:
                {
                    var request = new NetrShareEnumRequest(requestBytes);
                    var response = GetNetrShareEnumResponse(request);
                    return response.GetBytes();
                }
                case ServerServiceOpName.NetrShareGetInfo:
                {
                    var request = new NetrShareGetInfoRequest(requestBytes);
                    var response = GetNetrShareGetInfoResponse(request);
                    return response.GetBytes();
                }
                case ServerServiceOpName.NetrServerGetInfo:
                {
                    var request = new NetrServerGetInfoRequest(requestBytes);
                    var response = GetNetrWkstaGetInfoResponse(request);
                    return response.GetBytes();
                }
                default:
                    throw new UnsupportedOpNumException();
            }
        }

        public NetrShareEnumResponse GetNetrShareEnumResponse(NetrShareEnumRequest request)
        {
            var response = new NetrShareEnumResponse();
            switch (request.InfoStruct.Level)
            {
                case 0:
                {
                    // We ignore request.PreferedMaximumLength
                    var info = new ShareInfo0Container();
                    foreach (var shareName in _mShares) info.Add(new ShareInfo0Entry(shareName));
                    response.InfoStruct = new ShareEnum(info);
                    response.TotalEntries = (uint) _mShares.Count;
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 1:
                {
                    // We ignore request.PreferedMaximumLength
                    var info = new ShareInfo1Container();
                    foreach (var shareName in _mShares)
                        info.Add(new ShareInfo1Entry(shareName, new ShareTypeExtended(ShareType.DiskDrive)));
                    response.InfoStruct = new ShareEnum(info);
                    response.TotalEntries = (uint) _mShares.Count;
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 2:
                case 501:
                case 502:
                case 503:
                {
                    response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                    response.Result = Win32Error.ErrorNotSupported;
                    return response;
                }
                default:
                {
                    response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                    response.Result = Win32Error.ErrorInvalidLevel;
                    return response;
                }
            }
        }

        public NetrShareGetInfoResponse GetNetrShareGetInfoResponse(NetrShareGetInfoRequest request)
        {
            var shareIndex = IndexOfShare(request.NetName);

            var response = new NetrShareGetInfoResponse();
            if (shareIndex == -1)
            {
                response.InfoStruct = new ShareInfo(request.Level);
                response.Result = Win32Error.NerrNetNameNotFound;
                return response;
            }

            switch (request.Level)
            {
                case 0:
                {
                    var info = new ShareInfo0Entry(_mShares[shareIndex]);
                    response.InfoStruct = new ShareInfo(info);
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 1:
                {
                    var info = new ShareInfo1Entry(_mShares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive));
                    response.InfoStruct = new ShareInfo(info);
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 2:
                {
                    var info = new ShareInfo2Entry(_mShares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive));
                    response.InfoStruct = new ShareInfo(info);
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 501:
                case 502:
                case 503:
                case 1005:
                {
                    response.InfoStruct = new ShareInfo(request.Level);
                    response.Result = Win32Error.ErrorNotSupported;
                    return response;
                }
                default:
                {
                    response.InfoStruct = new ShareInfo(request.Level);
                    response.Result = Win32Error.ErrorInvalidLevel;
                    return response;
                }
            }
        }

        public NetrServerGetInfoResponse GetNetrWkstaGetInfoResponse(NetrServerGetInfoRequest request)
        {
            var response = new NetrServerGetInfoResponse();
            switch (request.Level)
            {
                case 100:
                {
                    var info = new ServerInfo100();
                    info.PlatformId = _mPlatformId;
                    info.ServerName.Value = _mServerName;
                    response.InfoStruct = new ServerInfo(info);
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 101:
                {
                    var info = new ServerInfo101();
                    info.PlatformId = _mPlatformId;
                    info.ServerName.Value = _mServerName;
                    info.VerMajor = _mVerMajor;
                    info.VerMinor = _mVerMinor;
                    info.Type = _mServerType;
                    info.Comment.Value = string.Empty;
                    response.InfoStruct = new ServerInfo(info);
                    response.Result = Win32Error.ErrorSuccess;
                    return response;
                }
                case 102:
                case 103:
                case 502:
                case 503:
                {
                    response.InfoStruct = new ServerInfo(request.Level);
                    response.Result = Win32Error.ErrorNotSupported;
                    return response;
                }
                default:
                {
                    response.InfoStruct = new ServerInfo(request.Level);
                    response.Result = Win32Error.ErrorInvalidLevel;
                    return response;
                }
            }
        }

        private int IndexOfShare(string shareName)
        {
            for (var index = 0; index < _mShares.Count; index++)
                if (_mShares[index].Equals(shareName, StringComparison.OrdinalIgnoreCase))
                    return index;

            return -1;
        }
    }
}