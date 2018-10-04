// <copyright file="Program.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallEquivalenceCheckerCmd
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using CommandLine;
    using Microsoft.FirewallAnalysis;

    /// <summary>
    /// Main entry point to checker command line tool.
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Returns a list of inconsistencies between two firewall files.
        /// </summary>
        /// <param name="options">Options controlling the check.</param>
        /// <returns>A list of firewall inconsistencies.</returns>
        public static List<WindowsFirewallInconsistency> CheckFirewalls(Options options)
        {
            Console.WriteLine("Parsing first firewall...");
            WindowsFirewall f1 = new WindowsFirewall
            {
                BlockByDefault = options.Firewall1BlockByDefault,
                Rules = WindowsFirewallRuleParser.Parse(File.ReadAllText(options.Firewall1Filepath), '\t').ToList()
            };

            Console.WriteLine("Parsing second firewall...");
            WindowsFirewall f2 = new WindowsFirewall
            {
                BlockByDefault = options.Firewall2BlockByDefault,
                Rules = WindowsFirewallRuleParser.Parse(File.ReadAllText(options.Firewall2Filepath), '\t').ToList()
            };

            Console.WriteLine("Running equivalence check...");
            return WindowsFirewallEquivalenceCheck.CheckEquivalence(f1, f2).Take(options.InconsistencyCount).ToList();
        }

        /// <summary>
        /// Prints the list of packets handled inconsistently between the two firewalls.
        /// </summary>
        /// <param name="inconsistencies">List of inconsistencies.</param>
        public static void PrintInconsistentPackets(List<WindowsFirewallInconsistency> inconsistencies)
        {
            Console.WriteLine("Inconsistently-handled packets:");
            Console.WriteLine("-------------------------------------------------------------------------");
            Console.WriteLine("|  PID |     Src Address | Src Port | Dest Port | Protocol | Allowed By |");
            Console.WriteLine("-------------------------------------------------------------------------");
            for (int i = 0; i < inconsistencies.Count; i++)
            {
                WindowsFirewallInconsistency inconsistency = inconsistencies[i];
                Console.WriteLine(
                    $"| {i, 4} " +
                    $"| {inconsistency.Packet.SourceAddress?.ToString() ?? "Any", 15} " +
                    $"| {inconsistency.Packet.SourcePort?.ToString() ?? "Any", 8} " +
                    $"| {inconsistency.Packet.DestinationPort?.ToString() ?? "Any", 9} " +
                    $"| {(null == inconsistency.Packet.Protocol ? "Any" : NetworkProtocol.GetProtocolName((int)inconsistency.Packet.Protocol)), 8} " +
                    $"| {(inconsistency.Allowed.Item1 ? "First" : "Second"), 10} |");
            }

            Console.WriteLine("-------------------------------------------------------------------------");
        }

        /// <summary>
        /// Prints list of rules matched by inconsistent packets.
        /// </summary>
        /// <param name="inconsistencies">List of inconsistencies.</param>
        public static void PrintRuleMatches(List<WindowsFirewallInconsistency> inconsistencies)
        {
            Console.WriteLine("Firewall rules matching inconsistently-handled packets:");
            Console.WriteLine("-------------------------------------------------------------------------");
            Console.WriteLine("|  PID | Firewall | Action | Rule Name                                  |");
            Console.WriteLine("-------------------------------------------------------------------------");
            for (int i = 0; i < inconsistencies.Count; i++)
            {
                WindowsFirewallInconsistency inconsistency = inconsistencies[i];
                foreach (WindowsFirewallRule rule in inconsistency.RuleMatches.Item1)
                {
                    Console.WriteLine(
                        $"| {i, 4} " +
                        $"| {"First", 8} " +
                        $"| {(rule.Allow ? "Allow" : "Block"), 6} " +
                        $"| {rule.Name.Substring(0, Math.Min(rule.Name.Length, 42)), -42} |");
                }

                foreach (WindowsFirewallRule rule in inconsistency.RuleMatches.Item2)
                {
                    Console.WriteLine(
                        $"| {i, 4} " +
                        $"| {"Second", 8} " +
                        $"| {(rule.Allow ? "Allow" : "Block"), 6} " +
                        $"| {rule.Name.Substring(0, Math.Min(rule.Name.Length, 42)), -42} |");
                }
            }

            Console.WriteLine("-------------------------------------------------------------------------");
        }

        /// <summary>
        /// Main entry point to checker command line tool.
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
            List<WindowsFirewallInconsistency> inconsistencies = Program.CheckFirewalls(options);

            if (!inconsistencies.Any())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Firewalls are equivalent.");
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Firewalls are NOT equivalent.");
                Console.ResetColor();
                Console.WriteLine();
                Program.PrintInconsistentPackets(inconsistencies);
                Console.WriteLine();
                Program.PrintRuleMatches(inconsistencies);
            }
        }
    }
}
