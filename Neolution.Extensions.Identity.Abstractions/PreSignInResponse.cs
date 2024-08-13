namespace Neolution.Extensions.Identity.Abstractions
{
    /// <summary>
    /// Represents the result of pre sign-in check.
    /// </summary>
    public class PreSignInResponse
    {
        /// <summary>
        /// Gets a <see cref="PreSignInResponse"/> that represents a successful pre sign-in check.
        /// </summary>
        /// <returns>A <see cref="PreSignInResponse"/> that represents a successful pre sign-in check.</returns>
        public static PreSignInResponse Success => new() { Succeeded = true };

        /// <summary>
        /// Gets a <see cref="PreSignInResponse"/> that represents a pre sign-in check that failed because
        /// the user was locked out.
        /// </summary>
        /// <returns>A <see cref="PreSignInResponse"/> that represents a pre sign-in check that failed due to the
        /// user being locked out.</returns>
        public static PreSignInResponse Lockout => new() { IsLockedOut = true };

        /// <summary>
        /// Gets a <see cref="PreSignInResponse"/> that represents a pre sign-in check that failed because
        /// the user is not allowed to sign-in.
        /// </summary>
        /// <returns>A <see cref="PreSignInResponse"/> that represents a pre sign-in check that failed because the
        /// user is not allowed to sign-in.</returns>
        public static PreSignInResponse NotAllowed => new() { IsNotAllowed = true };

        /// <summary>
        /// Gets or sets a value indicating whether returns a flag indication whether the pre sign-in check was successful.
        /// </summary>
        /// <value>True if the sign-in was successful, otherwise false.</value>
        public bool Succeeded { get; protected set; }

        /// <summary>
        /// Gets or sets a value indicating whether returns a flag indication whether the user attempting to pre sign-in is locked out.
        /// </summary>
        /// <value>True if the user attempting to pre sign-in is locked out, otherwise false.</value>
        public bool IsLockedOut { get; protected set; }

        /// <summary>
        /// Gets or sets a value indicating whether returns a flag indication whether the user attempting to pre sign-in is not allowed to sign-in.
        /// </summary>
        /// <value>True if the user attempting to pre sign-in is not allowed to sign-in, otherwise false.</value>
        public bool IsNotAllowed { get; protected set; }

        /// <summary>
        /// Converts the value of the current <see cref="PreSignInResponse"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of value of the current <see cref="PreSignInResponse"/> object.</returns>
        public override string ToString()
        {
            if (this.IsNotAllowed)
            {
                return "NotAllowed";
            }

            if (this.IsLockedOut)
            {
                return "Lockedout";
            }

            if (this.Succeeded)
            {
                return "Succeeded";
            }

            return string.Empty;
        }
    }
}
