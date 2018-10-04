// <copyright file="WindowsFirewallRuleTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis.Tests
{
    using System.Net;
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Microsoft.Z3;

    /// <summary>
    /// Unit tests for the <see cref="WindowsFirewallRule"/> class.
    /// </summary>
    [TestClass]
    public class WindowsFirewallRuleTest
    {
        /// <summary>
        /// Tests Z3 correctly binds to a single possible match for the rule.
        /// </summary>
        [TestMethod]
        public void TestSingle()
        {
            using (var ctx = new Context())
            {
                int localPort = 80;
                IPAddress remoteAddress = IPAddress.Parse("192.168.1.1");
                int remotePort = 128;
                int protocol = 6;
                string record = $"X\tYes\tAllow\t{localPort}\t{remoteAddress}\t{remotePort}\t{protocol}";
                WindowsFirewallRule rule = WindowsFirewallRuleParser.ParseRecord(
                    WindowsFirewallRuleParserTest.HeaderIndex,
                    record,
                    '\t');
                var packetVars = new WindowsFirewallPacketVariables(ctx);
                Solver s = ctx.MkSolver();
                s.Assert(rule.Matches(ctx, packetVars));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                var packet = new WindowsFirewallPacket(s.Model);
                Assert.AreEqual(remoteAddress, packet.SourceAddress);
                Assert.AreEqual(remotePort, packet.SourcePort);
                Assert.AreEqual(localPort, packet.DestinationPort);
                Assert.AreEqual(protocol, packet.Protocol);
            }
        }
    }
}
