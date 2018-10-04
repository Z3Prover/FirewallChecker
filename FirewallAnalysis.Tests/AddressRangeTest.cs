// <copyright file="AddressRangeTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis.Tests
{
    using System.Net;
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Microsoft.Z3;

    /// <summary>
    /// Unit tests for the <see cref="AddressRange"/> class.
    /// </summary>
    [TestClass]
    public class AddressRangeTest
    {
        /// <summary>
        /// Test Z3 finds an address value in a satisfiable range.
        /// </summary>
        [TestMethod]
        public void TestSatisfiableRange()
        {
            using (var ctx = new Context())
            {
                IPAddress low = IPAddress.Parse("127.0.0.1");
                IPAddress high = IPAddress.Parse("127.0.0.10");
                var range = new AddressRange
                {
                    Low = low,
                    High = high
                };

                string variableName = "address";
                BitVecExpr variable = ctx.MkConst(variableName, ctx.MkBitVecSort(32)) as BitVecExpr;
                Assert.IsNotNull(variable);
                Solver s = ctx.MkSolver();
                s.Assert(range.Contains(ctx, variable));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                IPAddress binding;
                Assert.IsTrue(RetrieveModelValue.TryRetrieveAddress(variableName, s.Model, out binding));
                Assert.IsTrue(AddressRangeTest.CompareAddresses(low, binding) >= 0);
                Assert.IsTrue(AddressRangeTest.CompareAddresses(high, binding) <= 0);
            }
        }

        /// <summary>
        /// Test Z3 binds to the single possible address value.
        /// </summary>
        [TestMethod]
        public void TestSingle()
        {
            using (var ctx = new Context())
            {
                IPAddress single = IPAddress.Parse("192.168.0.1");
                var range = new AddressRange
                {
                    Low = single,
                    High = single
                };

                string variableName = "address";
                BitVecExpr variable = ctx.MkConst(variableName, ctx.MkBitVecSort(32)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(range.Contains(ctx, variable));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                IPAddress binding;
                Assert.IsTrue(RetrieveModelValue.TryRetrieveAddress(variableName, s.Model, out binding));
                Assert.AreEqual(single, binding);
            }
        }

        /// <summary>
        /// Tests Z3 is unable to find an address in an invalid address range.
        /// </summary>
        [TestMethod]
        public void TestUnsatisfiableRange()
        {
            using (var ctx = new Context())
            {
                IPAddress low = IPAddress.Parse("192.168.0.1");
                IPAddress high = IPAddress.Parse("192.0.100.0");
                var range = new AddressRange
                {
                    Low = low,
                    High = high
                };

                string variableName = "address";
                BitVecExpr variable = ctx.MkConst(variableName, ctx.MkBitVecSort(32)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(range.Contains(ctx, variable));
                Status result = s.Check();
                Assert.AreEqual(Status.UNSATISFIABLE, result);
            }
        }

        /// <summary>
        /// Tests Z3 is unable to find an address outside the full range of addresses.
        /// </summary>
        [TestMethod]
        public void TestFullRange()
        {
            using (var ctx = new Context())
            {
                IPAddress low = IPAddress.Parse("0.0.0.0");
                IPAddress high = IPAddress.Parse("255.255.255.255");
                var range = new AddressRange
                {
                    Low = low,
                    High = high
                };

                string variableName = "address";
                BitVecExpr variable = ctx.MkConst(variableName, ctx.MkBitVecSort(32)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(ctx.MkNot(range.Contains(ctx, variable)));
                Status result = s.Check();
                Assert.AreEqual(Status.UNSATISFIABLE, result);
            }
        }

        /// <summary>
        /// Compares two IP addresses. Returns zero if equal, positive number if
        /// second greater than first, and negative if first greater than second.
        /// </summary>
        /// <param name="first">First IP address to compare.</param>
        /// <param name="second">Second IP address to compare.</param>
        /// <returns>A comparison between the given addresses.</returns>
        private static int CompareAddresses(IPAddress first, IPAddress second)
        {
            byte[] a = first.GetAddressBytes();
            byte[] b = second.GetAddressBytes();
            for (int i = 0; i < 4; i++)
            {
                if (a[i] != b[i])
                {
                    return b[i] - a[i];
                }
            }

            return 0;
        }
    }
}
