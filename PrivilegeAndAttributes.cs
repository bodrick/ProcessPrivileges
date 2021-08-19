using System;

namespace ProcessPrivileges
{
    /// <summary>Structure that links <see cref="Privilege"/> and <see cref="PrivilegeAttributes"/> together.</summary>
    public struct PrivilegeAndAttributes : IEquatable<PrivilegeAndAttributes>
    {
        internal PrivilegeAndAttributes(Privilege privilege, PrivilegeAttributes privilegeAttributes)
        {
            Privilege = privilege;
            PrivilegeAttributes = privilegeAttributes;
        }

        /// <summary>Gets the privilege.</summary>
        /// <value>The privilege.</value>
        public Privilege Privilege { get; }

        /// <summary>Gets the privilege attributes.</summary>
        /// <value>The privilege attributes.</value>
        public PrivilegeAttributes PrivilegeAttributes { get; }

        /// <summary>Gets the privilege state.</summary>
        /// <value>The privilege state.</value>
        /// <remarks>Derived from <see cref="PrivilegeAttributes"/>.</remarks>
        public PrivilegeState PrivilegeState => ProcessExtensions.GetPrivilegeState(PrivilegeAttributes);

        /// <summary>Compares two instances for inequality.</summary>
        /// <param name="first">First instance.</param>
        /// <param name="second">Second instance.</param>
        /// <returns>Value indicating inequality of instances.</returns>
        public static bool operator !=(PrivilegeAndAttributes first, PrivilegeAndAttributes second) => !first.Equals(second);

        /// <summary>Compares two instances for equality.</summary>
        /// <param name="first">First instance.</param>
        /// <param name="second">Second instance.</param>
        /// <returns>Value indicating equality of instances.</returns>
        public static bool operator ==(PrivilegeAndAttributes first, PrivilegeAndAttributes second) => first.Equals(second);

        /// <summary>Indicates whether this instance and a specified object are equal.</summary>
        /// <param name="obj">Another object to compare to.</param>
        /// <returns>Value indicating whether this instance and a specified object are equal.</returns>
        public override bool Equals(object obj) => obj is PrivilegeAttributes ? Equals((PrivilegeAttributes)obj) : false;

        /// <summary>Indicates whether this instance and another instance are equal.</summary>
        /// <param name="other">Another instance to compare to.</param>
        /// <returns>Value indicating whether this instance and another instance are equal.</returns>
        public bool Equals(PrivilegeAndAttributes other) => Privilege == other.Privilege && PrivilegeAttributes == other.PrivilegeAttributes;

        /// <summary>Returns the hash code for this instance.</summary>
        /// <returns>The hash code for this instance.</returns>
        public override int GetHashCode() => Privilege.GetHashCode() ^ PrivilegeAttributes.GetHashCode();
    }
}
