// <copyright file="RetrieveModelValue.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>

namespace Microsoft.FirewallAnalysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using Microsoft.Z3;

    /// <summary>
    /// Utility class to retrieve CLR value types from the Z3 model.
    /// </summary>
    public static class RetrieveModelValue
    {
        /// <summary>
        /// Attempts retrieval of an integer value from the Z3 model.
        /// </summary>
        /// <param name="variableName">Name of the variable in the model.</param>
        /// <param name="m">The Z3 model.</param>
        /// <param name="value">The retrieved value.</param>
        /// <returns>Whether retrieval was successful.</returns>
        public static bool TryRetrieveInteger(string variableName, Model m, out int value)
        {
            Dictionary<string, Expr> exprMap = m.ConstDecls.ToDictionary(c => c.Name.ToString(), m.ConstInterp);
            Expr variable;
            if (!exprMap.TryGetValue(variableName, out variable))
            {
                value = 0;
                return false;
            }

            if (!int.TryParse(variable.ToString(), out value))
            {
                value = 0;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Attempts retrieval of an IP address value from the Z3 model.
        /// </summary>
        /// <param name="variableName">Name of the variable in the model.</param>
        /// <param name="m">The Z3 model.</param>
        /// <param name="value">The retrieved value.</param>
        /// <returns>Whether retrieval was successful.</returns>
        public static bool TryRetrieveAddress(string variableName, Model m, out IPAddress value)
        {
            Dictionary<string, Expr> exprMap = m.ConstDecls.ToDictionary(c => c.Name.ToString(), m.ConstInterp);
            Expr variable;
            if (!exprMap.TryGetValue(variableName, out variable))
            {
                value = IPAddress.None;
                return false;
            }

            if (!IPAddress.TryParse(variable.ToString(), out value))
            {
                value = IPAddress.None;
                return false;
            }

            return true;
        }

        /// <summary>
        /// Attempts retrieval of a string value from the Z3 model.
        /// </summary>
        /// <param name="variableName">Name of the variable in the model.</param>
        /// <param name="m">The Z3 model.</param>
        /// <param name="value">The retrieved value.</param>
        /// <returns>Whether retrieval was successful.</returns>
        public static bool TryRetrieveString(string variableName, Model m, out string value)
        {
            Dictionary<string, Expr> exprMap = m.ConstDecls.ToDictionary(c => c.Name.ToString(), m.ConstInterp);
            Expr variable;
            if (!exprMap.TryGetValue(variableName, out variable))
            {
                value = string.Empty;
                return false;
            }

            value = variable.ToString();
            return true;
        }
    }
}
