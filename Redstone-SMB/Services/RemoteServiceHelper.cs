/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using RedstoneSmb.RPC.Enums;
using RedstoneSmb.RPC.PDU;
using RedstoneSmb.RPC.Structures;
using RedstoneSmb.Services.Exceptions;
using ByteReader = RedstoneSmb.Utilities.ByteUtils.ByteReader;

namespace RedstoneSmb.Services
{
    public class RemoteServiceHelper
    {
        public const int NdrTransferSyntaxVersion = 2;

        public const int BindTimeFeatureIdentifierVersion = 1;

        // v1 - DCE 1.1: Remote Procedure Call
        // v2 - [MS-RPCE] 2.2.4.12 NDR Transfer Syntax Identifier
        public static readonly Guid NdrTransferSyntaxIdentifier = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860");

        // v1 - [MS-RPCE] 3.3.1.5.3 - Bind Time Feature Negotiation
        // Windows will reject this:
        //private static readonly Guid BindTimeFeatureIdentifier1 = new Guid("6CB71C2C-9812-4540-0100-000000000000");
        // Windows will return NegotiationResult.NegotiateAck:
        public static readonly Guid BindTimeFeatureIdentifier3 = new Guid("6CB71C2C-9812-4540-0300-000000000000");

        private static uint _mAssociationGroupId = 1;

        public static BindAckPdu GetRpcBindResponse(BindPdu bindPdu, RemoteService service)
        {
            var bindAckPdu = new BindAckPdu();
            bindAckPdu.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindAckPdu.DataRepresentation = bindPdu.DataRepresentation;
            bindAckPdu.CallId = bindPdu.CallId;
            // See DCE 1.1: Remote Procedure Call - 12.6.3.6
            // The client should set the assoc_group_id field either to 0 (zero), to indicate a new association group,
            // or to the known value. When the server receives a value of 0, this indicates that the client
            // has requested a new association group, and it assigns a server unique value to the group.
            if (bindPdu.AssociationGroupId == 0)
            {
                bindAckPdu.AssociationGroupId = _mAssociationGroupId;
                _mAssociationGroupId++;
                if (_mAssociationGroupId == 0) _mAssociationGroupId++;
            }
            else
            {
                bindAckPdu.AssociationGroupId = bindPdu.AssociationGroupId;
            }

            bindAckPdu.SecondaryAddress = @"\PIPE\" + service.PipeName;
            bindAckPdu.MaxTransmitFragmentSize = bindPdu.MaxReceiveFragmentSize;
            bindAckPdu.MaxReceiveFragmentSize = bindPdu.MaxTransmitFragmentSize;
            foreach (var element in bindPdu.ContextList)
            {
                var resultElement = new ResultElement();
                if (element.AbstractSyntax.InterfaceUuid.Equals(service.InterfaceGuid))
                {
                    var index = IndexOfSupportedTransferSyntax(element.TransferSyntaxList);
                    if (index >= 0)
                    {
                        resultElement.Result = NegotiationResult.Acceptance;
                        resultElement.TransferSyntax = element.TransferSyntaxList[index];
                    }
                    else if (element.TransferSyntaxList.Contains(new SyntaxId(BindTimeFeatureIdentifier3, 1)))
                    {
                        // [MS-RPCE] 3.3.1.5.3
                        // If the server supports bind time feature negotiation, it MUST reply with the result
                        // field in the p_result_t structure of the bind_ack PDU equal to negotiate_ack.
                        resultElement.Result = NegotiationResult.NegotiateAck;
                        resultElement.Reason = RejectionReason.AbstractSyntaxNotSupported;
                    }
                    else
                    {
                        resultElement.Result = NegotiationResult.ProviderRejection;
                        resultElement.Reason = RejectionReason.ProposedTransferSyntaxesNotSupported;
                    }
                }
                else
                {
                    resultElement.Result = NegotiationResult.ProviderRejection;
                    resultElement.Reason = RejectionReason.AbstractSyntaxNotSupported;
                }

                bindAckPdu.ResultList.Add(resultElement);
            }

            return bindAckPdu;
        }

        private static int IndexOfSupportedTransferSyntax(List<SyntaxId> syntaxList)
        {
            var supportedTransferSyntaxes = new List<SyntaxId>();
            supportedTransferSyntaxes.Add(new SyntaxId(NdrTransferSyntaxIdentifier, 1));
            // [MS-RPCE] Version 2.0 data representation protocol:
            supportedTransferSyntaxes.Add(new SyntaxId(NdrTransferSyntaxIdentifier, 2));

            for (var index = 0; index < syntaxList.Count; index++)
                if (supportedTransferSyntaxes.Contains(syntaxList[index]))
                    return index;
            return -1;
        }

        public static List<Rpcpdu> GetRpcResponse(RequestPdu requestPdu, RemoteService service,
            int maxTransmitFragmentSize)
        {
            var result = new List<Rpcpdu>();
            byte[] responseBytes;
            try
            {
                responseBytes = service.GetResponseBytes(requestPdu.OpNum, requestPdu.Data);
            }
            catch (UnsupportedOpNumException)
            {
                var faultPdu = new FaultPdu();
                faultPdu.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment | PacketFlags.DidNotExecute;
                faultPdu.DataRepresentation = requestPdu.DataRepresentation;
                faultPdu.CallId = requestPdu.CallId;
                faultPdu.AllocationHint = Rpcpdu.CommonFieldsLength + FaultPdu.FaultFieldsLength;
                // Windows will return either nca_s_fault_ndr or nca_op_rng_error.
                faultPdu.Status = FaultStatus.OpRangeError;
                result.Add(faultPdu);
                return result;
            }

            var offset = 0;
            var maxPduDataLength =
                maxTransmitFragmentSize - Rpcpdu.CommonFieldsLength - ResponsePdu.ResponseFieldsLength;
            do
            {
                var responsePdu = new ResponsePdu();
                var pduDataLength = Math.Min(responseBytes.Length - offset, maxPduDataLength);
                responsePdu.DataRepresentation = requestPdu.DataRepresentation;
                responsePdu.CallId = requestPdu.CallId;
                responsePdu.AllocationHint = (uint) (responseBytes.Length - offset);
                responsePdu.Data = ByteReader.ReadBytes(responseBytes, offset, pduDataLength);
                if (offset == 0) responsePdu.Flags |= PacketFlags.FirstFragment;
                if (offset + pduDataLength == responseBytes.Length) responsePdu.Flags |= PacketFlags.LastFragment;
                result.Add(responsePdu);
                offset += pduDataLength;
            } while (offset < responseBytes.Length);

            return result;
        }
    }
}