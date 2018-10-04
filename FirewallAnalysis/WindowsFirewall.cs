// <copyright file="WindowsFirewall.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.Z3;

    /// <summary>
    /// A set of <see cref="WindowsFirewallRule"/> and logic linking them into
    /// a full working firewall.
    /// </summary>
    public class WindowsFirewall
    {
        /// <summary>
        /// Gets or sets the name of this firewall.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets whether packets matching no rules are blocked by default.
        /// </summary>
        public bool BlockByDefault { get; set; }

        /// <summary>
        /// Gets or sets the list of <see cref="WindowsFirewallRule"/>
        /// </summary>
        public List<WindowsFirewallRule> Rules { get; set; }

        /// <summary>
        /// Builds a boolean expression over free variables which is true only if the
        /// variables, once bound, represent a packet accepted by this firewall.
        /// This firewall accepts a packet if it matches zero block rules. If the
        /// <see cref="WindowsFirewall.BlockByDefault"/> setting is true, packets matching
        /// zero allow rules are blocked; otherwise, they are allowed.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="packet">The packet to process through this firewall.</param>
        /// <returns>A Z3 boolean expression.</returns>
        public BoolExpr Allows(Context ctx, WindowsFirewallPacketVariables packet)
        {
            IEnumerable<BoolExpr> blockRules =
                from rule in this.Rules
                where rule.Enabled
                where !rule.Allow
                select rule.Matches(ctx, packet);

            BoolExpr hasBlockRuleMatch = ctx.MkOr(blockRules.ToArray());

            if (!this.BlockByDefault)
            {
                return ctx.MkNot(hasBlockRuleMatch);
            }

            IEnumerable<BoolExpr> allowRules =
                from rule in this.Rules
                where rule.Enabled
                where rule.Allow
                select rule.Matches(ctx, packet);

            BoolExpr hasAllowRuleMatch = ctx.MkOr(allowRules.ToArray());

            return ctx.MkAnd(hasAllowRuleMatch, ctx.MkNot(hasBlockRuleMatch));
        }

        /// <summary>
        /// Returns the list of rules matching a packet.
        /// </summary>
        /// <param name="ctx">The Z3 context.</param>
        /// <param name="packetVariables">The packet variables over which an expression is created.</param>
        /// <param name="model">A specific binding of the packet variables.</param>
        /// <returns>A list of rules matching the packet variable binding.</returns>
        public IEnumerable<WindowsFirewallRule> GetMatches(Context ctx, WindowsFirewallPacketVariables packetVariables, Model model)
        {
            return from rule in this.Rules
                   where rule.Enabled
                   where model.Eval(rule.Matches(ctx, packetVariables)).IsTrue
                   select rule;
        }
    }
}
