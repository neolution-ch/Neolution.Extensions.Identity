namespace Neolution.Extensions.Identity
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Neolution.Extensions.Identity.Abstractions.Models;
    using Neolution.Extensions.Identity.Abstractions.Services;

    /// <inheritdoc />
    public class UserManagerFacade<TUser> : IUserManager<TUser>
        where TUser : ApplicationUser
    {
        /// <summary>
        /// The user manager.
        /// </summary>
        private readonly UserManager<TUser> manager;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserManagerFacade{TUser}"/> class.
        /// </summary>
        /// <param name="manager">The user manager.</param>
        public UserManagerFacade(UserManager<TUser> manager)
        {
            this.manager = manager;
        }

        /// <inheritdoc />
        public async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            return await this.manager.CheckPasswordAsync(user, password).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<TUser> FindByNameAsync(string userName)
        {
            return await this.manager.FindByNameAsync(userName).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<TUser> FindByIdAsync(string userId)
        {
            return await this.manager.FindByIdAsync(userId).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            return await this.manager.GetClaimsAsync(user).ConfigureAwait(false);
        }
    }
}
