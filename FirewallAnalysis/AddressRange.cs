// <copyright file="AddressRange.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Linq;
    using System.Net;
    using Microsoft.Z3;

    /// <summary>
    /// A range of IP addresses, as commonly found in firewall rules.
    /// </summary>
    public class AddressRange
    {
        /// <summary>
        /// Gets or sets the lower bound of this IP range, inclusive.
        /// </summary>
        public IPAddress Low { get; set; }

        /// <summary>
        /// Gets or sets the upper bound of this IP range, inclusive.
        /// </summary>
        public IPAddress High { get; set; }

        /// <summary>
        /// Converts <see cref="IPAddress"/> to bit vector understood by Z3.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="address">The address to convert.</param>
        /// <returns>A bit vector representation of the address.</returns>
        public static BitVecExpr AddressToBitVecExpr(Context ctx, IPAddress address)
        {
            // IPAddress.GetAddressBytes() function always returns bytes in network byte order (big-endian).
            // If this system is little-endian, we must reverse the bytes returned from IPAddress.GetAddressBytes().
            byte[] addressBytes = BitConverter.IsLittleEndian
                ? address.GetAddressBytes().Reverse().ToArray()
                : address.GetAddressBytes();
            uint addressAsUint = BitConverter.ToUInt32(addressBytes, 0);
            return ctx.MkNumeral(addressAsUint, ctx.MkBitVecSort(32)) as BitVecExpr;
        }

        /// <summary>
        /// Builds a boolean expression over the free variable which is true only if the
        /// variable, when bound, represent an IP address contained in this range.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="address">The address variable to check for inclusion in the range.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Contains(Context ctx, BitVecExpr address)
        {
            BoolExpr aboveLow = ctx.MkBVUGE(address, AddressRange.AddressToBitVecExpr(ctx, this.Low));
            BoolExpr belowHigh = ctx.MkBVULE(address, AddressRange.AddressToBitVecExpr(ctx, this.High));
            return ctx.MkAnd(aboveLow, belowHigh);
        }
    }
}

