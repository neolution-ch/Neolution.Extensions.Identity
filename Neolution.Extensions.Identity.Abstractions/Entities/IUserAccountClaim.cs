namespace Neolution.Extensions.Identity.Abstractions.Entities
{
    /// <summary>
    /// The user account claim.
    /// </summary>
    public interface IUserAccountClaim
    {
        /// <summary>
        /// Gets or sets the user account identifier.
        /// </summary>
        Guid UserAccountId { get; set; }

        /// <summary>
        /// Gets or sets the claim type.
        /// </summary>
        string Type { get; set; }

        /// <summary>
        /// Gets or sets the claim value.
        /// </summary>
        string Value { get; set; }

        /// <summary>
        /// Gets or sets the user account.
        /// </summary>
        IUserAccount UserAccount { get; set; }
    }
}
