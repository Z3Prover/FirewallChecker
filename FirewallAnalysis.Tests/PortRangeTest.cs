// <copyright file="PortRangeTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis.Tests
{
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Microsoft.Z3;

    /// <summary>
    /// Unit tests for the <see cref="PortRange"/> class.
    /// </summary>
    [TestClass]
    public class PortRangeTest
    {
        /// <summary>
        /// Test Z3 finds a port value in a satisfiable range.
        /// </summary>
        [TestMethod]
        public void TestSatisfiableRange()
        {
            using (var ctx = new Context())
            {
                int low = 8;
                int high = 16;
                var range = new PortRange
                {
                    Low = low,
                    High = high
                };

                string portVariableName = "port";
                BitVecExpr variable = ctx.MkConst(portVariableName, ctx.MkBitVecSort(16)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(range.Contains(ctx, variable));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                int binding;
                Assert.IsTrue(RetrieveModelValue.TryRetrieveInteger(portVariableName, s.Model, out binding));
                Assert.IsTrue(binding >= low);
                Assert.IsTrue(binding <= high);
            }
        }

        /// <summary>
        /// Tests Z3 finds a port value in a range containing only one port.
        /// </summary>
        [TestMethod]
        public void TestSingle()
        {
            using (var ctx = new Context())
            {
                int single = 64;
                var range = new PortRange
                {
                    Low = single,
                    High = single
                };

                string portVariableName = "port";
                BitVecExpr variable = ctx.MkConst(portVariableName, ctx.MkBitVecSort(16)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(range.Contains(ctx, variable));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                int binding;
                Assert.IsTrue(RetrieveModelValue.TryRetrieveInteger(portVariableName, s.Model, out binding));
                Assert.AreEqual(single, binding);
            }
        }

        /// <summary>
        /// Tests Z3 is unable to find a port value in an unsatisfiable port range.
        /// </summary>
        [TestMethod]
        public void TestUnsatisfiableRange()
        {
            using (var ctx = new Context())
            {
                var range = new PortRange
                {
                    Low = 16,
                    High = 8
                };

                string portVariableName = "port";
                BitVecExpr variable = ctx.MkConst(portVariableName, ctx.MkBitVecSort(16)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(range.Contains(ctx, variable));
                Status result = s.Check();
                Assert.AreEqual(Status.UNSATISFIABLE, result);
            }
        }

        /// <summary>
        /// Tests Z3 is unable to find a port value outside the full 16-bit port range.
        /// </summary>
        [TestMethod]
        public void TestFullRange()
        {
            using (var ctx = new Context())
            {
                var range = new PortRange
                {
                    Low = 0,
                    High = ushort.MaxValue
                };

                string portVariableName = "port";
                BitVecExpr variable = ctx.MkConst(portVariableName, ctx.MkBitVecSort(16)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(ctx.MkNot(range.Contains(ctx, variable)));
                Status result = s.Check();
                Assert.AreEqual(Status.UNSATISFIABLE, result);
            }
        }
    }
}
