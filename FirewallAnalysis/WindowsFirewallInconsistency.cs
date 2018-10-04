// <copyright file="WindowsFirewallInconsistency.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Report of a single inconsistency between two <see cref="WindowsFirewall"/> intances.
    /// </summary>
    public class WindowsFirewallInconsistency
    {
        /// <summary>
        /// Gets or sets the inconsistently-handled <see cref="WindowsFirewallPacket"/>.
        /// </summary>
        public WindowsFirewallPacket Packet { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="WindowsFirewall"/> instances.
        /// </summary>
        public Tuple<WindowsFirewall, WindowsFirewall> Firewalls { get; set; }

        /// <summary>
        /// Gets or sets whether each <see cref="WindowsFirewall"/> allowed the packet.
        /// </summary>
        public Tuple<bool, bool> Allowed { get; set; }

        /// <summary>
        /// Gets or sets the rules matched by the <see cref="WindowsFirewallPacket"/>.
        /// </summary>
        public Tuple<List<WindowsFirewallRule>, List<WindowsFirewallRule>> RuleMatches { get; set; }
    }
}
