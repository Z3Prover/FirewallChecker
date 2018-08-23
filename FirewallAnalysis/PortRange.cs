// <copyright file="PortRange.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using Microsoft.Z3;

    /// <summary>
    /// A range of ports, as commonly found in firewall rules.
    /// </summary>
    public class PortRange
    {
        /// <summary>
        /// Gets or sets the lower bound of this port range, inclusive.
        /// </summary>
        public int Low { get; set; }

        /// <summary>
        /// Gets or sets the upper bound of this port range, inclusive.
        /// </summary>
        public int High { get; set; }

        /// <summary>
        /// Converts port value to a bit vector expression understood by Z3.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="port">The port value to convert.</param>
        /// <returns>A bit vector expression understood by Z3.</returns>
        public static BitVecExpr PortToBitVecExpr(Context ctx, int port)
        {
            return ctx.MkNumeral(port, ctx.MkBitVecSort(16)) as BitVecExpr;
        }

        /// <summary>
        /// Builds a boolean expression over the free variable port, which is true
        /// only if port, when bound, is contained within this port range.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="port">The port to check for inclusion in this range.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Contains(Context ctx, BitVecExpr port)
        {
            BoolExpr aboveLow = ctx.MkBVUGE(port, PortRange.PortToBitVecExpr(ctx, this.Low));
            BoolExpr belowHigh = ctx.MkBVULE(port, PortRange.PortToBitVecExpr(ctx, this.High));
            return ctx.MkAnd(aboveLow, belowHigh);
        }
    }
}
