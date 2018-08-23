// <copyright file="WindowsFirewallRule.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using Microsoft.Z3;

    /// <summary>
    /// Represents a single Windows Firewall rule.
    /// </summary>
    public class WindowsFirewallRule
    {
        /// <summary>
        /// Gets or sets the name of this firewall rule.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets remote addresses matched by this rule.
        /// </summary>
        public AddressSet RemoteAddresses { get; set; }

        /// <summary>
        /// Gets or sets the remote ports matched by this rule.
        /// </summary>
        public PortSet RemotePorts { get; set; }

        /// <summary>
        /// Gets or sets the local ports matched by this rule.
        /// </summary>
        public PortSet LocalPorts { get; set; }

        /// <summary>
        /// Gets or sets the protocol matched by this rule.
        /// </summary>
        public NetworkProtocol Protocol { get; set; }

        /// <summary>
        /// Gets or sets whether this rule is enabled.
        /// </summary>
        public bool Enabled { get; set; }

        /// <summary>
        /// Gets or sets whether this rule allows a matching packet.
        /// </summary>
        public bool Allow { get; set; }

        /// <summary>
        /// Builds a boolean expression over free variables which is true only if the
        /// variables, once bound, represent a packet matching this rule.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="packet">The packet to match against this rule.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Matches(Context ctx, WindowsFirewallPacketVariables packet)
        {
            BoolExpr[] conjuncts =
            {
                this.RemoteAddresses.Contains(ctx, packet.SourceAddress),
                this.RemotePorts.Contains(ctx, packet.SourcePort),
                this.LocalPorts.Contains(ctx, packet.DestinationPort),
                this.Protocol.Matches(ctx, packet.Protocol)
            };

            return ctx.MkAnd(conjuncts);
        }
    }
}
