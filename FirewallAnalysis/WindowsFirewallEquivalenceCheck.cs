// <copyright file="WindowsFirewallEquivalenceCheck.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Z3;

    /// <summary>
    /// Checks whether two <see cref="WindowsFirewall"/> instances are equivalent.
    /// </summary>
    public class WindowsFirewallEquivalenceCheck
    {
        /// <summary>
        /// Checks equivalence of two <see cref="WindowsFirewall"/> instances.
        /// </summary>
        /// <param name="f1">First firewall.</param>
        /// <param name="f2">Second firewall.</param>
        /// <returns>A report detailing firewall differences, if any.</returns>
        public static IEnumerable<WindowsFirewallInconsistency> CheckEquivalence(WindowsFirewall f1, WindowsFirewall f2)
        {
            var pastInconsistencies = new List<WindowsFirewallPacket>();
            using (var ctx = new Context())
            {
                while (true)
                {
                    Solver s = ctx.MkSolver();
                    var packetVars = new WindowsFirewallPacketVariables(ctx);
                    BoolExpr firewallInequivalence = ctx.MkNot(ctx.MkIff(f1.Allows(ctx, packetVars), f2.Allows(ctx, packetVars)));
                    BoolExpr matchesPastInconsistency = ctx.MkOr(pastInconsistencies.Select(p => p.Matches(ctx, packetVars)).ToArray());
                    s.Assert(ctx.MkAnd(firewallInequivalence, ctx.MkNot(matchesPastInconsistency)));
                    if (Status.UNSATISFIABLE == s.Check())
                    {
                        break;
                    }

                    Model m = s.Model;
                    var packet = new WindowsFirewallPacket(m);
                    pastInconsistencies.Add(packet);
                    var inconsistency = new WindowsFirewallInconsistency
                    {
                        Packet = packet,
                        Firewalls = Tuple.Create(f1, f2),
                        Allowed =
                            Tuple.Create(m.Eval(f1.Allows(ctx, packetVars)).IsTrue, m.Eval(f2.Allows(ctx, packetVars)).IsTrue),
                        RuleMatches =
                            Tuple.Create(f1.GetMatches(ctx, packetVars, m).ToList(), f2.GetMatches(ctx, packetVars, m).ToList())
                    };

                    yield return inconsistency;
                }
            }
        }
    }
}
