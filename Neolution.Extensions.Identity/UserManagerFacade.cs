namespace Neolution.Extensions.Identity
{
    using System.Collections.Generic;
    using System.Globalization;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using Neolution.Extensions.Identity.Abstractions;

    /// <inheritdoc />
    public class UserManagerFacade<TUser> : IUserManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// The logger
        /// </summary>
        private readonly ILogger<UserManagerFacade<TUser>> logger;

        /// <summary>
        /// The manager
        /// </summary>
        private readonly UserManager<TUser> manager;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserManagerFacade{TUser}"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        /// <param name="manager">The manager.</param>
        public UserManagerFacade(ILogger<UserManagerFacade<TUser>> logger, UserManager<TUser> manager)
        {
            this.logger = logger;
            this.manager = manager;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> CreateAsync(TUser user) => await this.manager.CreateAsync(user).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> CreateAsync(TUser user, string password) => await this.manager.CreateAsync(user, password).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> UpdateAsync(TUser user)
        {
            var result = await this.manager.UpdateAsync(user).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return result;
            }

            this.logger.LogWarning("Could not update user with id={id}", user.Id);
            foreach (var error in result.Errors)
            {
                this.logger.LogDebug("Error: Code '{code}', Description: {description}", error.Code, error.Description);
            }

            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> DeleteAsync(TUser user) => await this.manager.DeleteAsync(user).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<TUser?> FindByIdAsync(Guid userId) => await this.manager.FindByIdAsync(userId.ToString("D", CultureInfo.InvariantCulture)).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<TUser?> FindByNameAsync(string userName) => await this.manager.FindByNameAsync(userName).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<bool> CheckPasswordAsync(TUser user, string password) => await this.manager.CheckPasswordAsync(user, password).ConfigureAwait(false);

        public async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword) => await this.manager.ChangePasswordAsync(user, currentPassword, newPassword).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> AddClaimAsync(TUser user, Claim claim) => await this.manager.AddClaimAsync(user, claim).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            var claimsToAdd = claims.ToList();

            if (this.logger.IsEnabled(LogLevel.Trace))
            {
                this.logger.LogTrace("Add claims for user id={id}", user.Id);
                foreach (var claim in claimsToAdd)
                {
                    this.logger.LogTrace("Add claim '{type}' with value='{value}'", claim.Type, claim.Value);
                }
            }

            var result = await this.manager.AddClaimsAsync(user, claimsToAdd).ConfigureAwait(false);
            if (result.Succeeded)
            {
                if (this.logger.IsEnabled(LogLevel.Trace))
                {
                    this.logger.LogTrace("Adding claims succeeded for user id={id}", user.Id);
                }

                return result;
            }

            if (this.logger.IsEnabled(LogLevel.Warning))
            {
                this.logger.LogWarning("Could not add claims for user with id={id}", user.Id);
            }

            if (this.logger.IsEnabled(LogLevel.Debug))
            {
                foreach (var error in result.Errors)
                {
                    this.logger.LogDebug("Error: Code '{code}', Description: {description}", error.Code, error.Description);
                }
            }

            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim) => await this.manager.ReplaceClaimAsync(user, claim, newClaim).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim) => await this.manager.RemoveClaimAsync(user, claim).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            var claimsToRemove = claims.ToList();

            if (this.logger.IsEnabled(LogLevel.Trace))
            {
                this.logger.LogTrace("Remove claims for user id={id}", user.Id);
                foreach (var claim in claimsToRemove)
                {
                    this.logger.LogTrace("Remove claim '{type}' with value='{value}'", claim.Type, claim.Value);
                }
            }

            var result = await this.manager.RemoveClaimsAsync(user, claimsToRemove).ConfigureAwait(false);
            if (result.Succeeded)
            {
                if (this.logger.IsEnabled(LogLevel.Trace))
                {
                    this.logger.LogTrace("Removing claims succeeded for user id={id}", user.Id);
                }

                return result;
            }

            if (this.logger.IsEnabled(LogLevel.Warning))
            {
                this.logger.LogWarning("Could not remove claims for user with id={id}", user.Id);
            }

            if (this.logger.IsEnabled(LogLevel.Debug))
            {
                foreach (var error in result.Errors)
                {
                    this.logger.LogDebug("Error: Code '{code}', Description: {description}", error.Code, error.Description);
                }
            }

            return result;
        }

        /// <inheritdoc />
        public async Task<IList<Claim>> GetClaimsAsync(TUser user) => await this.manager.GetClaimsAsync(user).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<TUser?> FindByEmailAsync(string email) => await this.manager.FindByEmailAsync(email).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token) => await this.manager.VerifyTwoFactorTokenAsync(user, tokenProvider, token).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider) => await this.manager.GenerateTwoFactorTokenAsync(user, tokenProvider).ConfigureAwait(false);

        /// <inheritdoc />
        public async Task<IdentityResult> UpdateSecurityStampAsync(TUser user) => await this.manager.UpdateSecurityStampAsync(user).ConfigureAwait(false);
    }
}
