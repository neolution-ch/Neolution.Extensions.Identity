namespace Neolution.Extensions.Identity.Abstractions.Entities
{
    using System;

    /// <summary>
    /// The minimal members of a user account
    /// </summary>
    public interface IUserAccount
    {
        /// <summary>
        /// Gets or sets the user account identifier.
        /// </summary>
        Guid UserAccountId { get; set; }

        /// <summary>
        /// Gets or sets the email.
        /// </summary>
        string Email { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        string Password { get; set; }
    }
}
