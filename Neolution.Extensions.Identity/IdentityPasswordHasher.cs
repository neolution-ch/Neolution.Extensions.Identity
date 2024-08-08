namespace Neolution.Extensions.Identity
{
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Options;
    using Neolution.Extensions.Identity.Abstractions.Options;

    /// <summary>
    /// Password hashing implementation for the ASP.NET Core Identity framework
    /// </summary>
    /// <typeparam name="TUserAccount">The type of the user account.</typeparam>
    /// <seealso cref="IPasswordHasher{TUserAccount}" />
    public class IdentityPasswordHasher<TUserAccount> : IPasswordHasher<TUserAccount>
        where TUserAccount : IdentityUser<Guid>
    {
        /// <summary>
        /// The work factor
        /// </summary>
        private readonly int workFactor;

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityPasswordHasher{TUserAccount}"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public IdentityPasswordHasher(IOptions<NeolutionIdentityOptions> options)
        {
            this.workFactor = options.Value.PasswordHasher.BCryptWorkFactor;
        }

        /// <inheritdoc />
        public string HashPassword(TUserAccount user, string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, this.workFactor);
        }

        /// <inheritdoc />
        public PasswordVerificationResult VerifyHashedPassword(TUserAccount user, string hashedPassword, string providedPassword)
        {
            if (BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword))
            {
                return PasswordVerificationResult.Success;
            }

            return PasswordVerificationResult.Failed;
        }
    }
}
