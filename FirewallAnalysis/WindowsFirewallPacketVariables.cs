// <copyright file="WindowsFirewallPacketVariables.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using Microsoft.Z3;

    /// <summary>
    /// A packet to be evaluated for match with <see cref="WindowsFirewallRule"/>.
    /// </summary>
    public class WindowsFirewallPacketVariables
    {
        /// <summary>
        /// Name of the source address variable in Z3.
        /// </summary>
        internal const string SourceAddressVariableName = "sourceAddress";

        /// <summary>
        /// Name of the source port variable in Z3.
        /// </summary>
        internal const string SourcePortVariableName = "sourcePort";

        /// <summary>
        /// Name of the destination port variable in Z3.
        /// </summary>
        internal const string DestinationPortVariableName = "destinationPort";

        /// <summary>
        /// Name of the protocol variable in Z3.
        /// </summary>
        internal const string ProtocolVariableName = "protocol";

        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsFirewallPacketVariables"/> class.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        public WindowsFirewallPacketVariables(Context ctx)
        {
            this.SourceAddress = ctx.MkConst(WindowsFirewallPacketVariables.SourceAddressVariableName, ctx.MkBitVecSort(32)) as BitVecExpr;
            this.SourcePort = ctx.MkConst(WindowsFirewallPacketVariables.SourcePortVariableName, ctx.MkBitVecSort(16)) as BitVecExpr;
            this.DestinationPort = ctx.MkConst(WindowsFirewallPacketVariables.DestinationPortVariableName, ctx.MkBitVecSort(16)) as BitVecExpr;
            this.Protocol = ctx.MkConst(WindowsFirewallPacketVariables.ProtocolVariableName, ctx.MkBitVecSort(8)) as BitVecExpr;
        }

        /// <summary>
        /// Gets or sets the source IPv4 address of this packet.
        /// </summary>
        public BitVecExpr SourceAddress { get; set; }

        /// <summary>
        /// Gets or sets the source port of this packet.
        /// </summary>
        public BitVecExpr SourcePort { get; set; }

        /// <summary>
        /// Gets or sets the destination port of this packet.
        /// </summary>
        public BitVecExpr DestinationPort { get; set; }

        /// <summary>
        /// Gets or sets the protocol of this packet.
        /// </summary>
        public BitVecExpr Protocol { get; set; }
    }
}
