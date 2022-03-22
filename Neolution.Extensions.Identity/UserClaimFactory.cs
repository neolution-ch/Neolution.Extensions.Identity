namespace Neolution.Extensions.Identity
{
    using System.Diagnostics.CodeAnalysis;
    using System.Security.Claims;
    using Neolution.Extensions.Identity.Abstractions.Services;

    /// <summary>
    /// Factory that converts claims from the persistence layer to authentication claims.
    /// </summary>
    /// <typeparam name="TClaimType">The type of the claim type.</typeparam>
    /// <seealso cref="IUserClaimFactory{TClaimType}" />
    public class UserClaimFactory<TClaimType> : IUserClaimFactory<TClaimType>
        where TClaimType : Enum
    {
        /// <summary>
        /// Creates the claim.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        /// <returns>The <see cref="Claim"/>.</returns>
        /// <exception cref="System.ArgumentNullException">type</exception>
        public Claim Create([DisallowNull] TClaimType type, string value)
        {
            if (type is null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            return this.Create(type.ToString(), value);
        }

        /// <summary>
        /// Creates the claim.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="value">The value.</param>
        /// <returns>The <see cref="Claim"/>.</returns>
        /// <exception cref="System.ArgumentNullException">type</exception>
        public Claim Create(string type, string? value)
        {
            if (type is null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            return new Claim(type, value ?? string.Empty);
        }
    }
}
