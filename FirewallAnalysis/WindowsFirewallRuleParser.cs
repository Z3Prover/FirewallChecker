// <copyright file="WindowsFirewallRuleParser.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;

    /// <summary>
    /// Parses Windows Firewall rule dump into <see cref="WindowsFirewallRule"/> list.
    /// </summary>
    public static class WindowsFirewallRuleParser
    {
        /// <summary>
        /// Header name for name of rule.
        /// </summary>
        internal const string RuleNameName = "Name";

        /// <summary>
        /// Header name for whether rule is enabled.
        /// </summary>
        internal const string EnabledHeaderName = "Enabled";

        /// <summary>
        /// Header name for action of the rule.
        /// </summary>
        internal const string PermissionHeaderName = "Action";

        /// <summary>
        /// Header name for the local port.
        /// </summary>
        internal const string LocalPortHeaderName = "Local Port";

        /// <summary>
        /// Header name for the remote address.
        /// </summary>
        internal const string RemoteAddressHeaderName = "Remote Address";

        /// <summary>
        /// Header name for the remote port.
        /// </summary>
        internal const string RemotePortHeaderName = "Remote Port";

        /// <summary>
        /// Header name for the protocol.
        /// </summary>
        internal const string ProtocolHeaderName = "Protocol";

        /// <summary>
        /// Gets all headers required to be present in the text.
        /// </summary>
        internal static string[] RequiredHeaders { get; } =
        {
            WindowsFirewallRuleParser.RuleNameName,
            WindowsFirewallRuleParser.EnabledHeaderName,
            WindowsFirewallRuleParser.PermissionHeaderName,
            WindowsFirewallRuleParser.LocalPortHeaderName,
            WindowsFirewallRuleParser.RemoteAddressHeaderName,
            WindowsFirewallRuleParser.RemotePortHeaderName,
            WindowsFirewallRuleParser.ProtocolHeaderName
        };

        /// <summary>
        /// Parses text from a Windows Firewall dump file into a list of <see cref="WindowsFirewallRule"/>.
        /// </summary>
        /// <param name="text">The text to parse.</param>
        /// <param name="separator">The character separating columns.</param>
        /// <returns>A list of <see cref="WindowsFirewallRule"/>.</returns>
        public static IEnumerable<WindowsFirewallRule> Parse(string text, char separator)
        {
            using (var reader = new StringReader(text))
            {
                Dictionary<string, int> headerIndex = ParseHeader(WindowsFirewallRuleParser.RequiredHeaders, reader.ReadLine(), separator);

                string line = reader.ReadLine();
                for (int i = 0; null != line; i++)
                {
                    WindowsFirewallRule rule;
                    try
                    {
                        rule = ParseRecord(headerIndex, line, separator);
                    }
                    catch (FormatException e)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"Skipping line {i + 2} - {e.Message}");
                        Console.ResetColor();
                        line = reader.ReadLine();
                        continue;
                    }

                    yield return rule;

                    line = reader.ReadLine();
                }
            }
        }

        /// <summary>
        /// Parses and verifies the file header.
        /// </summary>
        /// <param name="requiredHeaders">Columns which are required to be present in the header.</param>
        /// <param name="headerLine">The unparsed header.</param>
        /// <param name="separator">The character separating columns.</param>
        /// <returns>An index of column headers.</returns>
        public static Dictionary<string, int> ParseHeader(string[] requiredHeaders, string headerLine, char separator)
        {
            if (string.IsNullOrEmpty(headerLine))
            {
                throw new ArgumentNullException(nameof(headerLine));
            }

            string[] allHeaders = headerLine.Split(new[] { separator }, StringSplitOptions.None);
            var headerIndex = new Dictionary<string, int>();
            for (int i = 0; i < allHeaders.Length; i++)
            {
                headerIndex[allHeaders[i].Trim()] = i;
            }

            string[] missing = requiredHeaders.Except(headerIndex.Keys).ToArray();
            if (missing.Any())
            {
                throw new FormatException($"Failed to find required headers: {string.Join(", ", missing)}");
            }

            return headerIndex;
        }

        /// <summary>
        /// Parses and verifies a record.
        /// </summary>
        /// <param name="headerIndex">The column header index.</param>
        /// <param name="recordLine">The unparsed record.</param>
        /// <param name="separator">The character separating columns.</param>
        /// <returns>An instance of <see cref="WindowsFirewallRule"/>.</returns>
        public static WindowsFirewallRule ParseRecord(Dictionary<string, int> headerIndex, string recordLine, char separator)
        {
            if (string.IsNullOrEmpty(recordLine))
            {
                throw new ArgumentNullException(recordLine);
            }

            string[] record = recordLine.Split(new[] { separator }, StringSplitOptions.None);
            return new WindowsFirewallRule
            {
                Name = WindowsFirewallRuleParser.ParseName(record[headerIndex[RuleNameName]]),
                RemoteAddresses = WindowsFirewallRuleParser.ParseAddressSet(record[headerIndex[RemoteAddressHeaderName]]),
                RemotePorts = WindowsFirewallRuleParser.ParsePortSet(record[headerIndex[RemotePortHeaderName]]),
                LocalPorts = WindowsFirewallRuleParser.ParsePortSet(record[headerIndex[LocalPortHeaderName]]),
                Protocol = WindowsFirewallRuleParser.ParseNetworkProtocol(record[headerIndex[ProtocolHeaderName]]),
                Enabled = WindowsFirewallRuleParser.ParseEnabled(record[headerIndex[EnabledHeaderName]]),
                Allow = WindowsFirewallRuleParser.ParseAction(record[headerIndex[PermissionHeaderName]])
            };
        }

        /// <summary>
        /// Parses the name of the rule.
        /// </summary>
        /// <param name="text">Unparsed text.</param>
        /// <returns>The parsed name of the rule.</returns>
        private static string ParseName(string text)
        {
            return text.Trim();
        }

        /// <summary>
        /// Parses the <see cref="AddressSet"/>.
        /// </summary>
        /// <param name="text">Unparsed text.</param>
        /// <returns>The parsed <see cref="AddressSet"/>.</returns>
        private static AddressSet ParseAddressSet(string text)
        {
            string trimmed = text.Trim();
            if ("Any" == trimmed)
            {
                return new AddressSet
                {
                    ContainsAll = true
                };
            }

            // Parse list of individual addresses and/or address ranges.
            // e.g. "127.0.0.1-127.0.0.10, 192.168.0.0-192.168.0.10, 255.255.255.255"
            List<AddressRange> ranges = new List<AddressRange>();
            string[] split = trimmed.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string unparsedRange in split)
            {
                string trimmedUnparsedRange = unparsedRange.Trim();
                string[] rangeOrSingle = trimmedUnparsedRange.Split(new[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
                if (1 == rangeOrSingle.Length)
                {
                    IPAddress single = IPAddress.Parse(rangeOrSingle[0].Trim());
                    if (AddressFamily.InterNetworkV6 == single.AddressFamily)
                    {
                        throw new FormatException("IPv6 not supported.");
                    }

                    ranges.Add(new AddressRange
                    {
                        Low = single,
                        High = single
                    });
                }
                else
                {
                    var range = new AddressRange
                    {
                        Low = IPAddress.Parse(rangeOrSingle[0].Trim()),
                        High = IPAddress.Parse(rangeOrSingle[1].Trim())
                    };

                    if (AddressFamily.InterNetworkV6 == range.Low.AddressFamily ||
                        AddressFamily.InterNetworkV6 == range.High.AddressFamily)
                    {
                        throw new FormatException("IPv6 not supported.");
                    }

                    ranges.Add(new AddressRange
                    {
                        Low = IPAddress.Parse(rangeOrSingle[0].Trim()),
                        High = IPAddress.Parse(rangeOrSingle[1].Trim())
                    });
                }
            }

            return new AddressSet
            {
                ContainsAll = false,
                Ranges = ranges
            };
        }

        /// <summary>
        /// Parses the <see cref="PortSet"/>.
        /// </summary>
        /// <param name="text">Unparsed text.</param>
        /// <returns>The parsed <see cref="PortSet"/>.</returns>
        private static PortSet ParsePortSet(string text)
        {
            string trimmed = text.Trim();

            if (string.IsNullOrEmpty(trimmed))
            {
                throw new FormatException("Port is null or empty.");
            }

            if ("Any" == trimmed)
            {
                return new PortSet
                {
                    ContainsAll = true
                };
            }

            // Port macros used by Windows Firewall.
            string[] macros =
            {
                "RPC Endpoint Mapper",
                "RPC Dynamic Ports",
                "IPHTTPS",
                "Edge Traversal",
                "PlayTo Discovery"
            };

            if (macros.Contains(trimmed))
            {
                throw new FormatException($"Port macros are not supported: {trimmed}");
            }

            // Parse list of individual ports and/or port ranges.
            // e.g. "80, 8080, 20000-20008"
            List<PortRange> ranges = new List<PortRange>();
            string[] split = trimmed.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string unparsedRange in split)
            {
                string trimmedUnparsedRange = unparsedRange.Trim();
                string[] rangeOrSingle = trimmedUnparsedRange.Split(new[] { '-' }, StringSplitOptions.RemoveEmptyEntries);
                if (1 == rangeOrSingle.Length)
                {
                    int single = int.Parse(rangeOrSingle[0].Trim());
                    ranges.Add(new PortRange
                    {
                        Low = single,
                        High = single
                    });
                }
                else
                {
                    ranges.Add(new PortRange
                    {
                        Low = int.Parse(rangeOrSingle[0].Trim()),
                        High = int.Parse(rangeOrSingle[1].Trim())
                    });
                }
            }

            return new PortSet
            {
                ContainsAll = false,
                Ranges = ranges
            };
        }

        /// <summary>
        /// Parses the <see cref="NetworkProtocol"/>.
        /// </summary>
        /// <param name="text">Unparsed text.</param>
        /// <returns>The parsed <see cref="NetworkProtocol"/>.</returns>
        private static NetworkProtocol ParseNetworkProtocol(string text)
        {
            string trimmed = text.Trim();
            if ("Any" == trimmed)
            {
                return new NetworkProtocol
                {
                    Any = true
                };
            }

            int protocolNumber;
            if (!NetworkProtocol.TryGetProtocolNumber(trimmed, out protocolNumber))
            {
                protocolNumber = int.Parse(trimmed);
            }

            return new NetworkProtocol
            {
                Any = false,
                ProtocolNumber = protocolNumber
            };
        }

        /// <summary>
        /// Parses whether the rule is enabled.
        /// </summary>
        /// <param name="text">Unparsed text.</param>
        /// <returns>Whether the rule is enabled.</returns>
        private static bool ParseEnabled(string text)
        {
            return "Yes" == text.Trim();
        }

        /// <summary>
        /// Parses whether the rule blocks or allows packets.
        /// </summary>
        /// <param name="text">Unparsed text.</param>
        /// <returns>Whether the rule blocks or allows packets.</returns>
        private static bool ParseAction(string text)
        {
            string trimmed = text.Trim();
            switch (trimmed)
            {
                case "Allow":
                    return true;
                case "Block":
                    return false;
                default:
                    throw new FormatException($"Invalid rule action: {trimmed}");
            }
        }
    }
}
