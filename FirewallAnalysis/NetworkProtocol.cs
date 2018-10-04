// <copyright file="NetworkProtocol.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Z3;

    /// <summary>
    /// A network protocol specified in the 8-bit protocol field of an IPv4 packet header.
    /// <see href="http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml"/>
    /// </summary>
    public class NetworkProtocol
    {
        /// <summary>
        /// Gets or sets a value indicating whether this matches any protocol.
        /// </summary>
        public bool Any { get; set; }

        /// <summary>
        /// Gets or sets the ID of this network protocol.
        /// </summary>
        public int ProtocolNumber { get; set; }

        /// <summary>
        /// Converts a protocol number to a bit vector expression understood by Z3.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="protocolNumber">The protocol number to convert.</param>
        /// <returns>A bit vector representation of the protocol number.</returns>
        public static BitVecExpr ProtocolToBitVecExpr(Context ctx, int protocolNumber)
        {
            return ctx.MkNumeral(protocolNumber, ctx.MkBitVecSort(8)) as BitVecExpr;
        }

        /// <summary>
        /// Returns the human-readable IANA standard name of some common protocol types.
        /// </summary>
        /// <param name="protocolNumber">The protocol number for which to find a name.</param>
        /// <returns>The protocol name.</returns>
        public static string GetProtocolName(int protocolNumber)
        {
            // Numbers from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
            var protocolMap = new Dictionary<int, string>
            {
                { 0, "HOPOPT" },
                { 1, "ICMP" },
                { 2, "IGMP" },
                { 6, "TCP" },
                { 17, "UDP" },
                { 41, "IPv6" },
                { 43, "IPv6-Route" },
                { 44, "IPv6-Frag" },
                { 47, "GRE" },
                { 58, "IPv6-ICMP" },
                { 59, "IPv6-NoNxt" },
                { 60, "IPv6-Opts" },
                { 112, "VRRP" },
                { 113, "PGM" },
                { 115, "L2TP" }
            };

            string protocolName;
            if (!protocolMap.TryGetValue(protocolNumber, out protocolName))
            {
                protocolName = protocolNumber.ToString();
            }

            return protocolName;
        }

        /// <summary>
        /// Given a protocol name, attempts to find the IANA standard protocol number.
        /// </summary>
        /// <param name="protocolName">The network protocol name.</param>
        /// <param name="protocolNumber">The network protocol number.</param>
        /// <returns>Whether number resolution succeeded.</returns>
        public static bool TryGetProtocolNumber(string protocolName, out int protocolNumber)
        {
            // Numbers from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
            var protocolMap = new Dictionary<string, int>
            {
                { "HOPOPT", 0 },
                { "ICMP", 1 },
                { "ICMPv4", 1 },    // Note: name specific to Windows Firewall
                { "IGMP", 2 },
                { "TCP", 6 },
                { "UDP", 17 },
                { "IPv6", 41 },
                { "IPv6-Route", 43 },
                { "IPv6-Frag", 44 },
                { "GRE", 47 },
                { "IPv6-ICMP", 58 },
                { "ICMPv6", 58 },   // Note: name specific to Windows Firewall
                { "IPv6-NoNxt", 59 },
                { "IPv6-Opts", 60 },
                { "VRRP", 112 },
                { "PGM", 113 },
                { "L2TP", 115 }
            };

            return protocolMap.TryGetValue(protocolName, out protocolNumber);
        }

        /// <summary>
        /// Builds a boolean expression over the port variable which is true only if
        /// the protocol variable value, once bound, matches this protocol.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="protocol">The protocol variable to check for match.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Matches(Context ctx, BitVecExpr protocol)
        {
            if (this.Any)
            {
                return ctx.MkTrue();
            }

            return ctx.MkEq(protocol, NetworkProtocol.ProtocolToBitVecExpr(ctx, this.ProtocolNumber));
        }
    }
}

