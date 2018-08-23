// <copyright file="AddressSet.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Z3;

    /// <summary>
    /// A set of IP addresses.
    /// </summary>
    public class AddressSet
    {
        /// <summary>
        /// Gets or sets whether this address set contains all valid IP addresses.
        /// </summary>
        public bool ContainsAll { get; set; }

        /// <summary>
        /// Gets or sets the list of <see cref="AddressRange"/> comprising this address set.
        /// </summary>
        public List<AddressRange> Ranges { get; set; }

        /// <summary>
        /// Builds a boolean expression over the address variable which is true only if
        /// the address variable value, once bound, is contained in this address set.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="address">The address variable to check for inclusion.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Contains(Context ctx, BitVecExpr address)
        {
            if (this.ContainsAll)
            {
                return ctx.MkTrue();
            }

            return ctx.MkOr(this.Ranges.Select(range => range.Contains(ctx, address)).ToArray());
        }
    }
}
