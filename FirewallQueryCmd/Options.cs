// <copyright file="Options.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallQuery
{
    using CommandLine;

    /// <summary>
    /// Command line options handler.
    /// </summary>
    internal class Options
    {
        /// <summary>
        /// Gets or sets path to firewall rule file.
        /// </summary>
        [Option("firewall", Required = true, HelpText = "Path to tab-separated firewall rule file.")]
        public string FirewallFilepath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether firewall blocks packets by default.
        /// </summary>
        [Option("blockByDefault", Required = false, Default = true, HelpText = "Whether firewall blocks packets by default.")]
        public bool FirewallBlockByDefault { get; set; }

        /// <summary>
        /// Gets or sets the source address of the test packet.
        /// </summary>
        [Option("srcAddress", Required = true, HelpText = "Source IP address of test packet. [127.0.0.1, \"Any\", etc.]")]
        public string SourceAddress { get; set; }

        /// <summary>
        /// Gets or sets the source port of the test packet.
        /// </summary>
        [Option("srcPort", Required = true, HelpText = "Source port of test packet. [80, 8080, \"Any\", etc.]")]
        public string SourcePort { get; set; }

        /// <summary>
        /// Gets or sets the destination port of the test packet.
        /// </summary>
        [Option("dstPort", Required = true, HelpText = "Destination port of test packet. [80, 8080, \"Any\", etc.]")]
        public string DestinationPort { get; set; }

        /// <summary>
        /// Gets or sets the network protocol of the test packet.
        /// </summary>
        [Option("protocol", Required = false, HelpText = "Network protocol of test packet. [TCP, UDP, 23, \"Any\", etc.]")]
        public string Protocol { get; set; }
    }
}