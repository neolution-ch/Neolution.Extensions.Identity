﻿namespace Neolution.Extensions.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using Neolution.Extensions.Identity.Abstractions;

    /// <inheritdoc />
    public sealed class UserManagerFacade<TUser> : IUserManager<TUser>
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
        public async Task<IdentityResult> CreateAsync(TUser user)
        {
            var result = await this.manager.CreateAsync(user).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Creating user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            var result = await this.manager.CreateAsync(user, password).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Creating user with id={user.Id} using provided password");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> UpdateAsync(TUser user)
        {
            var result = await this.manager.UpdateAsync(user).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Updating user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> DeleteAsync(TUser user)
        {
            var result = await this.manager.DeleteAsync(user).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Deleting user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<TUser?> FindByIdAsync(Guid userId)
        {
            var user = await this.manager.FindByIdAsync(userId.ToString("D", CultureInfo.InvariantCulture)).ConfigureAwait(false);
            if (user != null)
            {
                this.logger.LogDebug("Finding user by id={userId} succeeded", userId);
            }
            else
            {
                this.logger.LogWarning("Finding user by id={userId} failed", userId);
            }

            return user;
        }

        /// <inheritdoc />
        public async Task<TUser?> FindByNameAsync(string userName)
        {
            var user = await this.manager.FindByNameAsync(userName).ConfigureAwait(false);
            if (user != null)
            {
                this.logger.LogDebug("Finding user by name={userName} succeeded", userName);
            }
            else
            {
                this.logger.LogWarning("Finding user by name={userName} failed", userName);
            }

            return user;
        }

        /// <inheritdoc />
        public async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            var result = await this.manager.CheckPasswordAsync(user, password).ConfigureAwait(false);
            if (result)
            {
                this.logger.LogDebug("Checking password for user with id={userId} succeeded", user.Id);
            }
            else
            {
                this.logger.LogWarning("Checking password for user with id={userId} failed", user.Id);
            }

            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
        {
            var result = await this.manager.ChangePasswordAsync(user, currentPassword, newPassword).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Changing password for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> AddClaimAsync(TUser user, Claim claim)
        {
            var result = await this.manager.AddClaimAsync(user, claim).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Adding claim '{claim.Type}' for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            var claimsToAdd = claims as List<Claim> ?? claims.ToList();
            this.logger.LogDebug("Preparing to add claims for user id={id}", user.Id);
            foreach (var claim in claimsToAdd)
            {
                this.logger.LogDebug("Adding claim '{type}' with value='{value}'", claim.Type, claim.Value);
            }

            var result = await this.manager.AddClaimsAsync(user, claimsToAdd).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Adding claims for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim)
        {
            var result = await this.manager.ReplaceClaimAsync(user, claim, newClaim).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Replacing claim for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim)
        {
            var result = await this.manager.RemoveClaimAsync(user, claim).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Removing claim '{claim.Type}' for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            var claimsToRemove = claims as List<Claim> ?? claims.ToList();
            this.logger.LogDebug("Preparing to remove claims for user id={id}", user.Id);
            foreach (var claim in claimsToRemove)
            {
                this.logger.LogDebug("Claim '{type}' with value='{value}' will be removed", claim.Type, claim.Value);
            }

            var result = await this.manager.RemoveClaimsAsync(user, claimsToRemove).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Removing claims for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            var claims = await this.manager.GetClaimsAsync(user).ConfigureAwait(false);
            if (claims == null || !claims.Any())
            {
                this.logger.LogDebug("No claims found for user with id={id}", user.Id);
                return new List<Claim>();
            }

            return claims;
        }

        /// <inheritdoc />
        public async Task<TUser?> FindByEmailAsync(string email)
        {
            var user = await this.manager.FindByEmailAsync(email).ConfigureAwait(false);
            if (user != null)
            {
                this.logger.LogDebug("Finding user by email={email} succeeded", email);
            }
            else
            {
                this.logger.LogWarning("Finding user by email={email} failed", email);
            }

            return user;
        }

        /// <inheritdoc />
        public async Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token)
        {
            var result = await this.manager.VerifyTwoFactorTokenAsync(user, tokenProvider, token).ConfigureAwait(false);
            if (result)
            {
                this.logger.LogDebug("Verifying two-factor token for user with id={userId} succeeded", user.Id);
            }
            else
            {
                this.logger.LogWarning("Verifying two-factor token for user with id={userId} failed", user.Id);
            }

            return result;
        }

        /// <inheritdoc />
        public async Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider)
        {
            var token = await this.manager.GenerateTwoFactorTokenAsync(user, tokenProvider).ConfigureAwait(false);
            if (string.IsNullOrEmpty(token))
            {
                this.logger.LogWarning("Generating two-factor token for user with id={id} failed", user.Id);
            }

            return token;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> UpdateSecurityStampAsync(TUser user)
        {
            var result = await this.manager.UpdateSecurityStampAsync(user).ConfigureAwait(false);
            this.LogIdentityResult(result, $"Updating security stamp for user with id={user.Id}");
            return result;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            this.manager.Dispose();
        }

        /// <summary>
        /// Logs the identity result.
        /// </summary>
        /// <param name="result">The identity result.</param>
        /// <param name="message">The message.</param>
        private void LogIdentityResult(IdentityResult result, string message)
        {
            if (result.Succeeded)
            {
                this.logger.LogDebug("{message} succeeded", message);
            }
            else
            {
                this.logger.LogWarning("{message} failed", message);
                this.logger.LogDebug("IdentityResult: {result}", result);
            }
        }
    }
}
