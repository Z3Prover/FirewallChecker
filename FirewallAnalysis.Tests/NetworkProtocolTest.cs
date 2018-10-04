// <copyright file="NetworkProtocolTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis.Tests
{
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Microsoft.Z3;

    /// <summary>
    /// Unit tests for the <see cref="NetworkProtocol"/> class.
    /// </summary>
    [TestClass]
    public class NetworkProtocolTest
    {
        /// <summary>
        /// Test case where <see cref="NetworkProtocol.Any"/> is true.
        /// </summary>
        [TestMethod]
        public void TestMatchAny()
        {
            using (var ctx = new Context())
            {
                var networkProtocol = new NetworkProtocol
                {
                    Any = true
                };

                string protocolVariableName = "protocol";
                BitVecExpr protocolVariable = ctx.MkConst(protocolVariableName, ctx.MkBitVecSort(8)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(ctx.MkNot(networkProtocol.Matches(ctx, protocolVariable)));
                Status result = s.Check();
                Assert.AreEqual(Status.UNSATISFIABLE, result);
            }
        }

        /// <summary>
        /// Tests Z3 correctly binds a variable to the protocol number.
        /// </summary>
        [TestMethod]
        public void TestMatchesSatisfiable()
        {
            using (var ctx = new Context())
            {
                int protocolNumber = 6;
                var networkProtocol = new NetworkProtocol
                {
                    Any = false,
                    ProtocolNumber = protocolNumber
                };

                string protocolVariableName = "protocol";
                BitVecExpr protocolVariable = ctx.MkConst(protocolVariableName, ctx.MkBitVecSort(8)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(networkProtocol.Matches(ctx, protocolVariable));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                int binding;
                Assert.IsTrue(RetrieveModelValue.TryRetrieveInteger(protocolVariableName, s.Model, out binding));
                Assert.AreEqual(protocolNumber, binding);
            }
        }

        /// <summary>
        /// Tests Z3 correctly avoids binding variable to protocol number.
        /// </summary>
        [TestMethod]
        public void TestMatchesUnsatisfiable()
        {
            using (var ctx = new Context())
            {
                int protocolNumber = 6;
                var networkProtocol = new NetworkProtocol
                {
                    Any = false,
                    ProtocolNumber = protocolNumber
                };

                string protocolVariableName = "protocol";
                BitVecExpr protocolVariable = ctx.MkConst(protocolVariableName, ctx.MkBitVecSort(8)) as BitVecExpr;
                Solver s = ctx.MkSolver();
                s.Assert(ctx.MkNot(networkProtocol.Matches(ctx, protocolVariable)));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                int binding;
                Assert.IsTrue(RetrieveModelValue.TryRetrieveInteger(protocolVariableName, s.Model, out binding));
                Assert.AreNotEqual(protocolNumber, binding);
            }
        }
    }
}
