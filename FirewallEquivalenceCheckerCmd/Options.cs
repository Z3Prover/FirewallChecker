// <copyright file="Options.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallEquivalenceCheckerCmd
{
    using CommandLine;

    /// <summary>
    /// Command line options handler.
    /// </summary>
    internal class Options
    {
        /// <summary>
        /// Gets or sets path to first firewall rule file.
        /// </summary>
        [Option("firewall1", Required = true, HelpText = "Path to first tab-separated firewall rule file.")]
        public string Firewall1Filepath { get; set; }

        /// <summary>
        /// Gets or sets path to second firewall rule file.
        /// </summary>
        [Option("firewall2", Required = true, HelpText = "Path to second tab-separated firewall rule file.")]
        public string Firewall2Filepath { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether second firewall blocks packets by default.
        /// </summary>
        [Option("blockByDefault1", Required = false, Default = true, HelpText = "Whether first firewall blocks packets by default.")]
        public bool Firewall1BlockByDefault { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether second firewall blocks packets by default.
        /// </summary>
        [Option("blockByDefault2", Required = false, Default = true, HelpText = "Whether second firewall blocks packets by default.")]
        public bool Firewall2BlockByDefault { get; set; }

        /// <summary>
        /// Gets or sets the number of inconsistencies to find.
        /// </summary>
        [Option("inconsistencyCount", Required = false, Default = 10, HelpText = "Number of inconsistencies to find.")]
        public int InconsistencyCount { get; set; }
    }
}
