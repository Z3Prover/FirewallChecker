// <copyright file="WindowsFirewallEquivalenceCheckTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis.Tests
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Unit tests for the <see cref="WindowsFirewallEquivalenceCheck"/> class.
    /// </summary>
    [TestClass]
    public class WindowsFirewallEquivalenceCheckTest
    {
        /// <summary>
        /// Tests that a single firewall is equivalent with itself.
        /// </summary>
        [TestMethod]
        public void TestSameFirewall()
        {
            string record = "X\tYes\tAllow\t80\t192.168.1.1\t128\t6";
            string record2 = "Y\tYes\tAllow\t8080\t127.0.0.1\t256\t6";
            string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}\n{record2}";
            var firewall = new WindowsFirewall
            {
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            var inconsistencies = WindowsFirewallEquivalenceCheck.CheckEquivalence(firewall, firewall);
            Assert.IsFalse(inconsistencies.Any());
        }

        /// <summary>
        /// Tests that two firewalls with the same rules are equivalent.
        /// </summary>
        [TestMethod]
        public void TestEqualFirewalls()
        {
            string record = "X\tYes\tAllow\t80\t192.168.1.1\t128\t6";
            string record2 = "Y\tYes\tAllow\t8080\t127.0.0.1\t256\t6";
            string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}\n{record2}";
            var f1 = new WindowsFirewall
            {
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            var f2 = new WindowsFirewall
            {
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            var inconstistencies = WindowsFirewallEquivalenceCheck.CheckEquivalence(f1, f2);
            Assert.IsFalse(inconstistencies.Any());
        }

        /// <summary>
        /// Tests that two firewalls with different rules but equal action are equivalent.
        /// </summary>
        [TestMethod]
        public void TestEquivalentFirewalls()
        {
            string record = "X\tYes\tAllow\t80\t192.168.1.0-192.168.1.10\t128\t6";
            string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}";
            var f1 = new WindowsFirewall
            {
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            record = "X\tYes\tAllow\t80\t192.168.1.0-192.168.1.5\t128\t6";
            string record2 = "Y\tYes\tAllow\t80\t192.168.1.6-192.168.1.10\t128\t6";
            text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}\n{record2}";
            var f2 = new WindowsFirewall
            {
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            var inconstistencies = WindowsFirewallEquivalenceCheck.CheckEquivalence(f1, f2);
            Assert.IsFalse(inconstistencies.Any());
        }

        /// <summary>
        /// Tests equivalence check of firewalls with a single packet difference.
        /// </summary>
        [TestMethod]
        public void TestSingleDifference()
        {
            int localPort = 80;
            int remotePort = 128;
            int protocol = 6;
            string record = $"X\tYes\tAllow\t{localPort}\t192.168.1.0-192.168.1.10\t{remotePort}\t{protocol}";
            string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}";
            var f1 = new WindowsFirewall
            {
                Name = "1",
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            record = $"X\tYes\tAllow\t{localPort}\t192.168.1.0-192.168.1.4\t{remotePort}\t{protocol}";
            string record2 = $"Y\tYes\tAllow\t{localPort}\t192.168.1.6-192.168.1.10\t{remotePort}\t{protocol}";
            text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}\n{record2}";
            var f2 = new WindowsFirewall
            {
                Name = "2",
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            var inconstistencies = WindowsFirewallEquivalenceCheck.CheckEquivalence(f1, f2).ToList();
            Assert.AreEqual(1, inconstistencies.Count);
            WindowsFirewallInconsistency inconsistency = inconstistencies.Single();
            Assert.AreEqual("1", inconsistency.Firewalls.Item1.Name);
            Assert.IsTrue(inconsistency.Allowed.Item1);
            Assert.AreEqual("2", inconsistency.Firewalls.Item2.Name);
            Assert.IsFalse(inconsistency.Allowed.Item2);
            Assert.AreEqual(1, inconsistency.RuleMatches.Item1.Count);
            Assert.AreEqual("X", inconsistency.RuleMatches.Item1.Single().Name);
            Assert.AreEqual(0, inconsistency.RuleMatches.Item2.Count);
            Assert.AreEqual(IPAddress.Parse("192.168.1.5"), inconsistency.Packet.SourceAddress);
            Assert.AreEqual(remotePort, inconsistency.Packet.SourcePort);
            Assert.AreEqual(localPort, inconsistency.Packet.DestinationPort);
            Assert.AreEqual(protocol, inconsistency.Packet.Protocol);
        }

        /// <summary>
        /// Tests equivalence check of firewalls with multiple packet differences.
        /// </summary>
        [TestMethod]
        public void TestMultipleDifferences()
        {
            int localPort = 8080;
            int remotePort = 256;
            int protocol = 17;
            string record = $"X\tYes\tAllow\t{localPort}\t255.255.255.0-255.255.255.15\t{remotePort}\t{protocol}";
            string text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}";
            var f1 = new WindowsFirewall
            {
                Name = "1",
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            record = $"X\tYes\tAllow\t{localPort}\t255.255.255.0-255.255.255.2\t{remotePort}\t{protocol}";
            string record2 = $"Y\tYes\tAllow\t{localPort}\t255.255.255.4-255.255.255.6\t{remotePort}\t{protocol}";
            string record3 = $"Y\tYes\tAllow\t{localPort}\t255.255.255.8-255.255.255.10\t{remotePort}\t{protocol}";
            string record4 = $"Y\tYes\tAllow\t{localPort}\t255.255.255.12-255.255.255.15\t{remotePort}\t{protocol}";
            text = $"{WindowsFirewallRuleParserTest.HeaderText}\n{record}\n{record2}\n{record3}\n{record4}";
            var f2 = new WindowsFirewall
            {
                Name = "2",
                BlockByDefault = true,
                Rules = WindowsFirewallRuleParser.Parse(text, '\t').ToList()
            };

            var inconsistencies = WindowsFirewallEquivalenceCheck.CheckEquivalence(f1, f2).ToList();
            var expected = new HashSet<IPAddress>
            {
                IPAddress.Parse("255.255.255.3"),
                IPAddress.Parse("255.255.255.7"),
                IPAddress.Parse("255.255.255.11")
            };

            Assert.AreEqual(3, inconsistencies.Count);
            foreach (var inconsistency in inconsistencies)
            {
                Assert.AreEqual("1", inconsistency.Firewalls.Item1.Name);
                Assert.IsTrue(inconsistency.Allowed.Item1);
                Assert.AreEqual("2", inconsistency.Firewalls.Item2.Name);
                Assert.IsFalse(inconsistency.Allowed.Item2);
                Assert.AreEqual(1, inconsistency.RuleMatches.Item1.Count);
                Assert.AreEqual("X", inconsistency.RuleMatches.Item1.Single().Name);
                Assert.AreEqual(0, inconsistency.RuleMatches.Item2.Count);
                Assert.AreEqual(remotePort, inconsistency.Packet.SourcePort);
                Assert.AreEqual(localPort, inconsistency.Packet.DestinationPort);
                Assert.AreEqual(protocol, inconsistency.Packet.Protocol);
                Assert.IsTrue(expected.Contains(inconsistency.Packet.SourceAddress));
                expected.Remove(inconsistency.Packet.SourceAddress);
            }

            Assert.IsFalse(expected.Any());
        }
    }
}
