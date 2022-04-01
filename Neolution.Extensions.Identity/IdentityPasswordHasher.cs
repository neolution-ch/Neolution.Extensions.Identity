namespace Neolution.Extensions.Identity
{
    using Microsoft.AspNetCore.Identity;
    using Neolution.Abstractions.Security;

    /// <summary>
    /// Password hashing implementation for the ASP.NET Core Identity framework
    /// </summary>
    public class IdentityPasswordHasher<TUserAccount> : IPasswordHasher<TUserAccount> 
        where TUserAccount : IdentityUser<Guid>
    {
        /// <summary>
        /// The password hasher
        /// </summary>
        private readonly IPasswordHasher passwordHasher;

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityPasswordHasher{TUserAccount}"/> class.
        /// </summary>
        /// <param name="passwordHasher">The password hasher.</param>
        public IdentityPasswordHasher(IPasswordHasher passwordHasher)
        {
            this.passwordHasher = passwordHasher;
        }

        /// <inheritdoc />
        public string HashPassword(TUserAccount user, string password)
        {
            return this.passwordHasher.CreateHash(password);
        }

        /// <inheritdoc />
        public PasswordVerificationResult VerifyHashedPassword(TUserAccount user, string hashedPassword, string providedPassword)
        {
            if (this.passwordHasher.VerifyHash(hashedPassword, providedPassword))
            {
                return PasswordVerificationResult.Success;
            }

            return PasswordVerificationResult.Failed;
        }
    }
}
