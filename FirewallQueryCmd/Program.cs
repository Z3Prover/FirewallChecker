// <copyright file="Program.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallQuery
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using CommandLine;
    using Microsoft.FirewallAnalysis;
    using Microsoft.Z3;

    /// <summary>
    /// Main entry point to query command line tool.
    /// </summary>
    internal class Program
    {
        public static void TestPacket(Options options)
        {
            Console.WriteLine("Parsing firewall rules...");
            WindowsFirewall firewall = new WindowsFirewall
            {
                BlockByDefault = options.FirewallBlockByDefault,
                Rules = WindowsFirewallRuleParser.Parse(File.ReadAllText(options.FirewallFilepath), '\t').ToList()
            };

            int protocolNumber;
            bool anyProtocol = false;
            if (!NetworkProtocol.TryGetProtocolNumber(options.Protocol, out protocolNumber))
            {
                if (string.Equals("Any", options.Protocol, StringComparison.InvariantCultureIgnoreCase))
                {
                    anyProtocol = true;
                }
                else
                {
                    protocolNumber = int.Parse(options.Protocol);
                }
            }

            WindowsFirewallPacket packet = new WindowsFirewallPacket
            {
                SourceAddress = IPAddress.Parse(options.SourceAddress),
                SourcePort = string.Equals("Any", options.SourcePort, StringComparison.InvariantCultureIgnoreCase) ? null : (int?)int.Parse(options.SourcePort),
                DestinationPort = string.Equals("Any", options.DestinationPort, StringComparison.InvariantCultureIgnoreCase) ? null : (int?)int.Parse(options.DestinationPort),
                Protocol = anyProtocol ? null : (int?)protocolNumber
            };

            Console.WriteLine("Checking action of firewall on packet...");
            using (var ctx = new Context())
            {
                Solver s = ctx.MkSolver();
                var packetVars = new WindowsFirewallPacketVariables(ctx);
                s.Assert(packet.Matches(ctx, packetVars));
                s.Check();

                if (s.Model.Eval(firewall.Allows(ctx, packetVars)).IsTrue)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Packet is allowed by firewall.");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Packet is NOT allowed by firewall.");
                    Console.ResetColor();
                }

                List<WindowsFirewallRule> ruleMatches = firewall.GetMatches(ctx, packetVars, s.Model).ToList();
                if (!ruleMatches.Any())
                {
                    Console.WriteLine("No firewall rules match the test packet.");
                    return;
                }

                Console.WriteLine();
                Console.WriteLine("Firewall rules matching the test packet:");
                Console.WriteLine("-------------------------------------------------------------------------");
                Console.WriteLine("| Action | Rule Name                                                    |");
                Console.WriteLine("-------------------------------------------------------------------------");
                foreach (WindowsFirewallRule rule in ruleMatches)
                {
                    Console.WriteLine(
                        $"| {(rule.Allow ? "Allow" : "Block"), 6} " +
                        $"| {rule.Name.Substring(0, Math.Min(rule.Name.Length, 60)), -60} |");
                }

                Console.WriteLine("-------------------------------------------------------------------------");
            }
        }

        /// <summary>
        /// Main entry point to query command line tool.
        /// </summary>
        /// <param name="args">The command line arguments.</param>
        private static void Main(string[] args)
        {
            ParserResult<Options> result = Parser.Default.ParseArguments<Options>(args);
            if (ParserResultType.NotParsed == result.Tag)
            {
                return;
            }

            Parsed<Options> success = (Parsed<Options>)result;
            Options options = success.Value;
            Program.TestPacket(options);
        }
    }
}