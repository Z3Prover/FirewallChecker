// <copyright file="PortSet.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Z3;

    /// <summary>
    /// A set of ports.
    /// </summary>
    public class PortSet
    {
        /// <summary>
        /// Gets or sets a value indicating whether this port set contains all valid ports.
        /// </summary>
        public bool ContainsAll { get; set; }

        /// <summary>
        /// Gets or sets the list of <see cref="PortRange"/> comprising this port set.
        /// </summary>
        public List<PortRange> Ranges { get; set; }

        /// <summary>
        /// Builds a boolean expression over the port variable which is true only if
        /// the port variable value, once bound, is contained in this port set.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="port">The port variable to check for inclusion.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Contains(Context ctx, BitVecExpr port)
        {
            if (this.ContainsAll)
            {
                return ctx.MkTrue();
            }

            return ctx.MkOr(this.Ranges.Select(range => range.Contains(ctx, port)).ToArray());
        }
    }
}
