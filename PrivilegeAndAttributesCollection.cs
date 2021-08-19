using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace ProcessPrivileges
{
    /// <summary>Read-only collection of privilege and attributes.</summary>
    [Serializable]
    public sealed class PrivilegeAndAttributesCollection : ReadOnlyCollection<PrivilegeAndAttributes>
    {
        internal PrivilegeAndAttributesCollection(IList<PrivilegeAndAttributes> list)
            : base(list)
        {
        }

        /// <summary>Returns a <see cref="string"/> representation of the collection.</summary>
        /// <returns><see cref="string"/> representation of the collection.</returns>
        public override string ToString()
        {
            var stringBuilder = new StringBuilder();
            var maxPrivilegeLength = this.Max(privilegeAndAttributes => privilegeAndAttributes.Privilege.ToString().Length);
            foreach (var privilegeAndAttributes in this)
            {
                stringBuilder.Append(privilegeAndAttributes.Privilege);
                var paddingLength = maxPrivilegeLength - privilegeAndAttributes.Privilege.ToString().Length;
                var padding = new char[paddingLength];
                for (var i = 0; i < paddingLength; i++)
                {
                    padding[i] = ' ';
                }

                stringBuilder.Append(padding);
                stringBuilder.Append(" => ");
                stringBuilder.AppendLine(privilegeAndAttributes.PrivilegeAttributes.ToString());
            }

            return stringBuilder.ToString();
        }
    }
}
