namespace Neolution.Extensions.Identity.Security
{
    using Microsoft.AspNetCore.Identity;
    using Neolution.Abstractions.Security;

    /// <summary>
    /// Password hashing implementation für das ASP.NET Core Identity framework
    /// </summary>
    /// <typeparam name="TUser">The application user type.</typeparam>
    public class IdentityPasswordHasher<TUser> : IPasswordHasher<TUser>
        where TUser : class
    {
        /// <summary>
        /// The password hasher
        /// </summary>
        private readonly IPasswordHasher passwordHasher;

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityPasswordHasher{TUser}"/> class.
        /// </summary>
        /// <param name="passwordHasher">The password provider.</param>
        public IdentityPasswordHasher(IPasswordHasher passwordHasher)
        {
            this.passwordHasher = passwordHasher;
        }

        /// <inheritdoc />
        public string HashPassword(TUser user, string password)
        {
            return this.passwordHasher.CreateHash(password);
        }

        /// <inheritdoc />
        public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (this.passwordHasher.VerifyHash(hashedPassword, providedPassword))
            {
                return PasswordVerificationResult.Success;
            }

            return PasswordVerificationResult.Failed;
        }
    }
}
