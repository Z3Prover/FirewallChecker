// <copyright file="WindowsFirewallTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis.Tests
{
    using System.Linq;
    using System.Net;
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Microsoft.Z3;

    /// <summary>
    /// Unit tests for the <see cref="WindowsFirewall"/> class.
    /// </summary>
    [TestClass]
    public class WindowsFirewallTest
    {
        /// <summary>
        /// Tests a firewall allowing only a single packet.
        /// </summary>
        [TestMethod]
        public void TestAllowSingle()
        {
            using (var ctx = new Context())
            {
                int localPort = 80;
                IPAddress remoteAddress = IPAddress.Parse("192.168.1.1");
                int remotePort = 128;
                int protocol = 6;
                string record = $"X\tYes\tAllow\t{localPort}\t{remoteAddress}\t{remotePort}\t{protocol}";
                string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}";
                var firewall = new WindowsFirewall
                {
                    BlockByDefault = true,
                    Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
                };

                var packetVars = new WindowsFirewallPacketVariables(ctx);
                Solver s = ctx.MkSolver();
                s.Assert(firewall.Allows(ctx, packetVars));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                var packet = new WindowsFirewallPacket(s.Model);
                Assert.AreEqual(remoteAddress, packet.SourceAddress);
                Assert.AreEqual(remotePort, packet.SourcePort);
                Assert.AreEqual(localPort, packet.DestinationPort);
                Assert.AreEqual(protocol, packet.Protocol);
            }
        }

        /// <summary>
        /// Tests firewall correctly handles conflicts; block rule wins.
        /// </summary>
        [TestMethod]
        public void TestConflict()
        {
            using (var ctx = new Context())
            {
                int localPort = 80;
                IPAddress remoteAddress = IPAddress.Parse("192.168.1.1");
                int remotePort = 128;
                int protocol = 6;
                string allowRecord = $"X\tYes\tAllow\t{localPort}\t{remoteAddress}\t{remotePort}\t{protocol}";
                string blockRecord = $"Y\tYes\tBlock\t{localPort}\t{remoteAddress}\t{remotePort}\t{protocol}";
                string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{allowRecord}\n{blockRecord}";
                var firewall = new WindowsFirewall
                {
                    BlockByDefault = true,
                    Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
                };

                var packetVars = new WindowsFirewallPacketVariables(ctx);
                Solver s = ctx.MkSolver();
                s.Assert(firewall.Allows(ctx, packetVars));
                Status result = s.Check();
                Assert.AreEqual(Status.UNSATISFIABLE, result);
            }
        }

        /// <summary>
        /// Tests allow-by-default functionality.
        /// </summary>
        [TestMethod]
        public void TestAllowByDefault()
        {
            using (var ctx = new Context())
            {
                IPAddress allowed = IPAddress.Parse("128.0.0.1");
                string lowerBlock = "X\tYes\tBlock\tAny\t0.0.0.0-128.0.0.0\tAny\tAny";
                string upperBlock = "Y\tYes\tBlock\tAny\t128.0.0.2-255.255.255.255\tAny\tAny";
                string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{lowerBlock}\n{upperBlock}";
                var firewall = new WindowsFirewall
                {
                    BlockByDefault = false,
                    Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
                };

                var packetVars = new WindowsFirewallPacketVariables(ctx);
                Solver s = ctx.MkSolver();
                s.Assert(firewall.Allows(ctx, packetVars));
                Status result = s.Check();
                Assert.AreEqual(Status.SATISFIABLE, result);
                var packet = new WindowsFirewallPacket(s.Model);
                Assert.AreEqual(allowed, packet.SourceAddress);
                Assert.AreEqual(null, packet.SourcePort);
                Assert.AreEqual(null, packet.DestinationPort);
                Assert.AreEqual(null, packet.Protocol);
            }
        }
    }
}
