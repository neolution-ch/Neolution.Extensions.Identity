namespace Neolution.Extensions.Identity.Abstractions
{
    /// <summary>
    /// Required members for database context factories used with Identity tables.
    /// </summary>
    public interface IIdentityDbContextFactory
    {
        /// <summary>
        /// Creates the database context.
        /// </summary>
        /// <returns>The database context.</returns>
        public IIdentityDbContext CreateContext();

        /// <summary>
        /// Creates the read only database context.
        /// </summary>
        /// <returns>The read only database context</returns>
        public IIdentityDbContext CreateReadOnlyContext();
    }
}
