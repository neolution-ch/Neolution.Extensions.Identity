namespace Neolution.Extensions.Identity.Abstractions
{
    using Microsoft.EntityFrameworkCore;
    using Neolution.Extensions.Identity.Abstractions.Entities;

    /// <summary>
    /// The database context when working with Identity tables
    /// </summary>
    /// <seealso cref="System.IAsyncDisposable" />
    public interface IIdentityDbContext : IAsyncDisposable
    {
        /// <summary>
        /// Gets or sets the user accounts.
        /// </summary>
        public DbSet<IUserAccount> UserAccounts { get; set; }

        /// <summary>
        /// Gets or sets the user account claims.
        /// </summary>
        public DbSet<IUserAccountClaim> UserAccountClaims { get; set; }
    }
}
