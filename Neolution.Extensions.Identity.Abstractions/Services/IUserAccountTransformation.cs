namespace Neolution.Extensions.Identity.Abstractions.Services
{
    using Neolution.Extensions.Identity.Abstractions.Entities;
    using Neolution.Extensions.Identity.Abstractions.Models;

    /// <summary>
    /// Transforms the user account to the application user.
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public interface IUserAccountTransformation<out TUser>
        where TUser : ApplicationUser
    {
        /// <summary>
        /// Creates the application user based on the user entity.
        /// </summary>
        /// <param name="userAccount">The user account.</param>
        /// <returns>The application user.</returns>
        TUser CreateApplicationUser(IUserAccount userAccount);
    }
}
