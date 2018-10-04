// <copyright file="WindowsFirewallPacket.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using Microsoft.Z3;

    /// <summary>
    /// Values found in a typical packet examined by Windows Firewall.
    /// </summary>
    public class WindowsFirewallPacket
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsFirewallPacket"/> class.
        /// </summary>
        public WindowsFirewallPacket()
        {
            this.SourceAddress = null;
            this.SourcePort = null;
            this.DestinationPort = null;
            this.Protocol = null;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsFirewallPacket"/> class
        /// from the variables in the model.
        /// </summary>
        /// <param name="m">A Z3 model.</param>
        public WindowsFirewallPacket(Model m)
        {
            IPAddress sourceAddress;
            this.SourceAddress = RetrieveModelValue.TryRetrieveAddress(WindowsFirewallPacketVariables.SourceAddressVariableName, m, out sourceAddress)
                ? sourceAddress
                : null;

            int sourcePort;
            this.SourcePort = RetrieveModelValue.TryRetrieveInteger(WindowsFirewallPacketVariables.SourcePortVariableName, m, out sourcePort)
                ? (int?)sourcePort
                : null;

            int destinationPort;
            this.DestinationPort = RetrieveModelValue.TryRetrieveInteger(WindowsFirewallPacketVariables.DestinationPortVariableName, m, out destinationPort)
                ? (int?)destinationPort
                : null;

            int protocol;
            this.Protocol = RetrieveModelValue.TryRetrieveInteger(WindowsFirewallPacketVariables.ProtocolVariableName, m, out protocol)
                ? (int?)protocol
                : null;
        }

        /// <summary>
        /// Gets or sets the source address of this packet.
        /// </summary>
        public IPAddress SourceAddress { get; set; }

        /// <summary>
        /// Gets or sets the source port of this packet.
        /// </summary>
        public int? SourcePort { get; set; }

        /// <summary>
        /// Gets or sets the destination port of this packet.
        /// </summary>
        public int? DestinationPort { get; set; }

        /// <summary>
        /// Gets or sets the protocol of this packet.
        /// </summary>
        public int? Protocol { get; set; }

        /// <summary>
        /// Builds a string representation of this packet.
        /// </summary>
        /// <returns>A string representation of this packet.</returns>
        public new string ToString()
        {
            return $"Src Address: {this.SourceAddress?.ToString() ?? "Any"} "
                   + $"| Src Port: {this.SourcePort?.ToString() ?? "Any"} "
                   + $"| Dest Port: {this.DestinationPort?.ToString() ?? "Any"} "
                   + $"| Protocol: {this.Protocol?.ToString() ?? "Any"}";
        }

        /// <summary>
        /// Creates a boolean expression expressing the conditions under which the given packet
        /// variables match this specific packet.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="packet">The packet variables over which to form an expression.</param>
        /// <returns>A boolean expression.</returns>
        public BoolExpr Matches(Context ctx, WindowsFirewallPacketVariables packet)
        {
            var conjuncts = new List<BoolExpr>();
            if (this.SourceAddress != null)
            {
                conjuncts.Add(ctx.MkEq(packet.SourceAddress, AddressRange.AddressToBitVecExpr(ctx, this.SourceAddress)));
            }

            if (this.SourcePort != null)
            {
                conjuncts.Add(ctx.MkEq(packet.SourcePort, PortRange.PortToBitVecExpr(ctx, (int)this.SourcePort)));
            }

            if (this.DestinationPort != null)
            {
                conjuncts.Add(ctx.MkEq(packet.DestinationPort, PortRange.PortToBitVecExpr(ctx, (int)this.DestinationPort)));
            }

            if (this.Protocol != null)
            {
                conjuncts.Add(ctx.MkEq(packet.Protocol, NetworkProtocol.ProtocolToBitVecExpr(ctx, (int)this.Protocol)));
            }

            return ctx.MkAnd(conjuncts.ToArray());
        }
    }
}
