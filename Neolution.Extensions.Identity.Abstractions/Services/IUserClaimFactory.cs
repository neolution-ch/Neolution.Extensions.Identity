namespace Neolution.Extensions.Identity.Abstractions.Services
{
    using System.Diagnostics.CodeAnalysis;
    using System.Security.Claims;

    /// <summary>
    /// Factory to create claims.
    /// </summary>
    /// <typeparam name="TClaimType">The type of the claim type.</typeparam>
    public interface IUserClaimFactory<in TClaimType>
    {
        /// <summary>
        /// Creates the specified type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        /// <returns>The <see cref="Claim"/>.</returns>
        Claim Create([DisallowNull] TClaimType type, string value);

        /// <summary>
        /// Creates the specified type.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        /// <returns>The <see cref="Claim"/>.</returns>
        Claim Create(string type, string? value);
    }
}
