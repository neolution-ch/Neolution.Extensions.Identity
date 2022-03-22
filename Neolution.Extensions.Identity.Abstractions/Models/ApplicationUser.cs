namespace Neolution.Extensions.Identity.Abstractions.Models
{
    /// <summary>
    /// The application user.
    /// </summary>
    public class ApplicationUser
    {
        /// <summary>
        /// Gets or sets the user identifier.
        /// </summary>
        public Guid UserId { get; set; }

        /// <summary>
        /// Gets or sets the login user name.
        /// </summary>
        public string? UserName { get; set; }

        /// <summary>
        /// Gets or sets the password hash.
        /// </summary>
        public string? PasswordHash { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether MFA is enabled.
        /// </summary>
        /// <value>
        ///   <c>true</c> if MFA is enabled; otherwise, <c>false</c>.
        /// </value>
        public bool MfaEnabled { get; set; }
    }
}
