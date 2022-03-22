namespace Neolution.Extensions.Identity.Stores
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;
    using Neolution.Extensions.Identity.Abstractions;
    using Neolution.Extensions.Identity.Abstractions.Models;
    using Neolution.Extensions.Identity.Abstractions.Services;

    /// <summary>
    /// Neolution User Store implementation.
    /// IMPORTANT: When working on this class, please refer to https://github.com/dotnet/aspnetcore/blob/master/src/Identity/EntityFrameworkCore/src/UserStore.cs as the reference implementation
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    /// <typeparam name="TClaimType">The type of the claim type.</typeparam>
    /// <seealso cref="IUserPasswordStore{TUser}" />
    /// <seealso cref="IUserClaimStore{TUser}" />
    public sealed class UserStore<TUser, TClaimType> : IUserPasswordStore<TUser>, IUserClaimStore<TUser>
        where TUser : ApplicationUser
        where TClaimType : Enum
    {
        /// <summary>
        /// The database context factory.
        /// </summary>
        private readonly IIdentityDbContextFactory contextFactory;

        /// <summary>
        /// The user claim factory
        /// </summary>
        private readonly IUserClaimFactory<TClaimType> userClaimFactory;

        /// <summary>
        /// The user account transformation
        /// </summary>
        private readonly IUserAccountTransformation<TUser> userAccountTransformation;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserStore{TUser, TClaimType}"/> class.
        /// </summary>
        /// <param name="contextFactory">The context factory.</param>
        /// <param name="userClaimFactory">The user claim factory.</param>
        /// <param name="userAccountTransformation">The user account transformation.</param>
        public UserStore(IIdentityDbContextFactory contextFactory, IUserClaimFactory<TClaimType> userClaimFactory, IUserAccountTransformation<TUser> userAccountTransformation)
        {
            this.contextFactory = contextFactory;
            this.userClaimFactory = userClaimFactory;
            this.userAccountTransformation = userAccountTransformation;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            // Nothing to dispose
        }

        /// <inheritdoc />
        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserId.ToString());
        }

        /// <inheritdoc />
        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName) !;
        }

        /// <inheritdoc />
        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            // We do not allow to set user names
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName?.ToUpperInvariant()) !;
        }

        /// <inheritdoc />
        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            // We do not set normalized fields
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            // Users cannot create/register themselves. Therefore we do not expose that use case through this API
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            // Users cannot update themselves. Therefore we just return a success without doing anything
            return Task.FromResult(IdentityResult.Success);
        }

        /// <inheritdoc />
        public Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            // Users cannot delete themselves. Therefore we do not expose that use case through this API
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Get user from database
            await using var context = this.contextFactory.CreateReadOnlyContext();
            var user = context.UserAccounts.IgnoreQueryFilters().FirstOrDefault(x => x.UserAccountId == new Guid(userId));

            if (user == null)
            {
                return null!;
            }

            var result = this.userAccountTransformation.CreateApplicationUser(user);
            return await Task.FromResult(result).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Get user from database
            await using var context = this.contextFactory.CreateReadOnlyContext();
            var user = context.UserAccounts.IgnoreQueryFilters().FirstOrDefault(x => x.Email == normalizedUserName);

            if (user == null)
            {
                return (await Task.FromResult(null as TUser).ConfigureAwait(false)) !;
            }

            var result = this.userAccountTransformation.CreateApplicationUser(user);
            return await Task.FromResult(result).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(user.PasswordHash) !;
        }

        /// <inheritdoc />
        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user?.PasswordHash != null);
        }

        /// <inheritdoc />
        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return this.GetClaimsInternalAsync(user, cancellationToken);
        }

        /// <inheritdoc />
        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return this.GetUsersForClaimInternalAsync(claim, cancellationToken);
        }

        /// <summary>
        /// Gets the users for the specified claim.
        /// </summary>
        /// <param name="claim">The claim.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The users assigned with the specified claim.</returns>
        private async Task<IList<TUser>> GetUsersForClaimInternalAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await using var context = this.contextFactory.CreateReadOnlyContext();
            var users = context.UserAccountClaims.IgnoreQueryFilters().Where(x => x.Type == claim.Type && x.Value == claim.Value).Select(x => x.UserAccount).ToList();

            // Map Users to ApplicationUsers
            IList<TUser> result = users.Select(this.userAccountTransformation.CreateApplicationUser).ToList();

            return await Task.FromResult(result).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets the claims asynchronously.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The claims.</returns>
        private async Task<IList<Claim>> GetClaimsInternalAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            await using var context = this.contextFactory.CreateReadOnlyContext();
            return await context.UserAccountClaims.IgnoreQueryFilters()
                .Where(x => x.UserAccountId == user.UserId)
                .Select(claim => this.userClaimFactory.Create(claim.Type, claim.Value))
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
