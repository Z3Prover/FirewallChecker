// <copyright file="WindowsFirewallRuleParserTest.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using Microsoft.FirewallAnalysis;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Unit tests for the <see cref="WindowsFirewallRuleParser"/> class.
    /// </summary>
    [TestClass]
    public class WindowsFirewallRuleParserTest
    {
        /// <summary>
        /// Gets a map from column header to row index.
        /// </summary>
        internal static Dictionary<string, int> HeaderIndex { get; } = new Dictionary<string, int>
        {
            { WindowsFirewallRuleParser.RuleNameName, 0 },
            { WindowsFirewallRuleParser.EnabledHeaderName, 1 },
            { WindowsFirewallRuleParser.PermissionHeaderName, 2 },
            { WindowsFirewallRuleParser.LocalPortHeaderName, 3 },
            { WindowsFirewallRuleParser.RemoteAddressHeaderName, 4 },
            { WindowsFirewallRuleParser.RemotePortHeaderName, 5 },
            { WindowsFirewallRuleParser.ProtocolHeaderName, 6 }
        };

        /// <summary>
        /// Gets unparsed header text corresponding to <see cref="WindowsFirewallRuleParserTest.HeaderIndex"/>.
        /// </summary>
        internal static string HeaderText
        {
            get
            {
                var reverseIndexed = new string[WindowsFirewallRuleParserTest.HeaderIndex.Count];
                foreach (KeyValuePair<string, int> pair in WindowsFirewallRuleParserTest.HeaderIndex)
                {
                    reverseIndexed[pair.Value] = pair.Key;
                }

                return string.Join("\t", reverseIndexed);
            }
        }

        /// <summary>
        /// Tests header is correctly parsed.
        /// </summary>
        [TestMethod]
        public void TestParseHeader()
        {
            Dictionary<string, int> indexed = WindowsFirewallRuleParser.ParseHeader(
                WindowsFirewallRuleParser.RequiredHeaders,
                WindowsFirewallRuleParserTest.HeaderText,
                '\t');

            foreach (KeyValuePair<string, int> pair in WindowsFirewallRuleParserTest.HeaderIndex)
            {
                Assert.IsTrue(indexed.ContainsKey(pair.Key));
                Assert.AreEqual(pair.Value, indexed[pair.Key]);
            }
        }

        /// <summary>
        /// Tests parsing of a simple rule with only single ports and addresses.
        /// </summary>
        [TestMethod]
        public void TestParseRuleSingle()
        {
            int localPort = 80;
            IPAddress remoteAddress = IPAddress.Parse("192.168.1.1");
            int remotePort = 128;
            string record = $"X\tYes\tAllow\t{localPort}\t{remoteAddress}\t{remotePort}\tTCP";
            WindowsFirewallRule rule = WindowsFirewallRuleParser.ParseRecord(
                WindowsFirewallRuleParserTest.HeaderIndex,
                record,
                '\t');
            Assert.AreEqual("X", rule.Name);
            Assert.IsTrue(rule.Enabled);
            Assert.IsTrue(rule.Allow);
            Assert.AreEqual(1, rule.LocalPorts.Ranges.Count);
            Assert.AreEqual(localPort, rule.LocalPorts.Ranges.Single().Low);
            Assert.AreEqual(localPort, rule.LocalPorts.Ranges.Single().High);
            Assert.AreEqual(1, rule.RemotePorts.Ranges.Count);
            Assert.AreEqual(remotePort, rule.RemotePorts.Ranges.Single().Low);
            Assert.AreEqual(remotePort, rule.RemotePorts.Ranges.Single().High);
            Assert.AreEqual(1, rule.RemoteAddresses.Ranges.Count);
            Assert.AreEqual(remoteAddress, rule.RemoteAddresses.Ranges.Single().Low);
            Assert.AreEqual(remoteAddress, rule.RemoteAddresses.Ranges.Single().High);
            Assert.AreEqual(6, rule.Protocol.ProtocolNumber);
        }

        /// <summary>
        /// Tests parsing of a rule with ranges of ports and addresses.
        /// </summary>
        [TestMethod]
        public void TestParseRuleRanges()
        {
            int localPortLow = 80;
            int localPortHigh = 8080;
            IPAddress remoteAddressLow = IPAddress.Parse("64.32.16.8");
            IPAddress remoteAddressHigh = IPAddress.Parse("128.64.32.16");
            int remotePortLow = 128;
            int remotePortHigh = 256;
            string record = $"X\tYes\tAllow\t{localPortLow}-{localPortHigh}\t" +
                            $"{remoteAddressLow}-{remoteAddressHigh}\t" +
                            $"{remotePortLow}-{remotePortHigh}\tUDP";
            WindowsFirewallRule rule = WindowsFirewallRuleParser.ParseRecord(
                WindowsFirewallRuleParserTest.HeaderIndex,
                record,
                '\t');
            Assert.AreEqual(1, rule.LocalPorts.Ranges.Count);
            Assert.AreEqual(localPortLow, rule.LocalPorts.Ranges.Single().Low);
            Assert.AreEqual(localPortHigh, rule.LocalPorts.Ranges.Single().High);
            Assert.AreEqual(1, rule.RemotePorts.Ranges.Count);
            Assert.AreEqual(remotePortLow, rule.RemotePorts.Ranges.Single().Low);
            Assert.AreEqual(remotePortHigh, rule.RemotePorts.Ranges.Single().High);
            Assert.AreEqual(1, rule.RemoteAddresses.Ranges.Count);
            Assert.AreEqual(remoteAddressLow, rule.RemoteAddresses.Ranges.Single().Low);
            Assert.AreEqual(remoteAddressHigh, rule.RemoteAddresses.Ranges.Single().High);
            Assert.AreEqual(17, rule.Protocol.ProtocolNumber);
        }
    }
}
