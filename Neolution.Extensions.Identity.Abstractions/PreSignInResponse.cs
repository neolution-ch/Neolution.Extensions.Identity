namespace Neolution.Extensions.Identity.Abstractions
{
    /// <summary>
    /// Represents the result of a sign-in operation.
    /// </summary>
    public class PreSignInResponse
    {
        /// <summary>
        /// Gets a <see cref="SignInResponse"/> that represents a successful sign-in.
        /// </summary>
        /// <returns>A <see cref="SignInResponse"/> that represents a successful sign-in.</returns>
        public static PreSignInResponse Success => new() { Succeeded = true };

        /// <summary>
        /// Gets a <see cref="SignInResponse"/> that represents a sign-in attempt that failed because
        /// the user was locked out.
        /// </summary>
        /// <returns>A <see cref="SignInResponse"/> that represents sign-in attempt that failed due to the
        /// user being locked out.</returns>
        public static PreSignInResponse Lockout => new() { IsLockedOut = true };

        /// <summary>
        /// Gets a <see cref="SignInResponse"/> that represents a sign-in attempt that failed because
        /// the user is not allowed to sign-in.
        /// </summary>
        /// <returns>A <see cref="SignInResponse"/> that represents sign-in attempt that failed due to the
        /// user is not allowed to sign-in.</returns>
        public static PreSignInResponse NotAllowed => new() { IsNotAllowed = true };

        /// <summary>
        /// Gets or sets a value indicating whether returns a flag indication whether the sign-in was successful.
        /// </summary>
        /// <value>True if the sign-in was successful, otherwise false.</value>
        public bool Succeeded { get; protected set; }

        /// <summary>
        /// Gets or sets a value indicating whether returns a flag indication whether the user attempting to sign-in is locked out.
        /// </summary>
        /// <value>True if the user attempting to sign-in is locked out, otherwise false.</value>
        public bool IsLockedOut { get; protected set; }

        /// <summary>
        /// Gets or sets a value indicating whether returns a flag indication whether the user attempting to sign-in is not allowed to sign-in.
        /// </summary>
        /// <value>True if the user attempting to sign-in is not allowed to sign-in, otherwise false.</value>
        public bool IsNotAllowed { get; protected set; }

        /// <summary>
        /// Converts the value of the current <see cref="SignInResponse"/> object to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of value of the current <see cref="SignInResponse"/> object.</returns>
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
