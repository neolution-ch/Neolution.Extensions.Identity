namespace Neolution.Extensions.Identity.Abstractions
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// Provides the APIs for managing user in a persistence store.
    /// </summary>
    /// <typeparam name="TUser">The type of the user account.</typeparam>
    public interface IUserManager<TUser> : IDisposable
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// Gets a value indicating whether the backing user store supports user lock-outs.
        /// </summary>
        /// <value>
        /// true if the backing user store supports user lock-outs, otherwise false.
        /// </value>
        bool SupportsUserLockout { get; }

        /// <summary>
        /// Gets the <see cref="IdentityOptions"/> used to configure Identity.
        /// </summary>
        public IdentityOptions Options { get; }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the backing store with no password,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> CreateAsync(TUser user);

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the backing store with given password,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="password">The password for the user to hash and store.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> CreateAsync(TUser user, string password);

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the backing store.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> UpdateAsync(TUser user);

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the backing store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> DeleteAsync(TUser user);

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        Task<TUser?> FindByIdAsync(Guid userId);

        /// <summary>
        /// Finds and returns a user, if any, who has the specified user name.
        /// </summary>
        /// <param name="userName">The user name to search for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userName"/> if it exists.
        /// </returns>
        Task<TUser?> FindByNameAsync(string userName);

        /// <summary>
        /// Returns a flag indicating whether the given <paramref name="password"/> is valid for the
        /// specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose password should be validated.</param>
        /// <param name="password">The password to validate</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing true if
        /// the specified <paramref name="password" /> matches the one store for the <paramref name="user"/>,
        /// otherwise false.</returns>
        Task<bool> CheckPasswordAsync(TUser user, string password);

        /// <summary>
        /// Changes a user's password after confirming the specified <paramref name="currentPassword"/> is correct,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose password should be set.</param>
        /// <param name="currentPassword">The current password to validate before changing.</param>
        /// <param name="newPassword">The new password to set for the specified <paramref name="user"/>.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword);

        /// <summary>
        /// Adds the specified <paramref name="claim"/> to the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claim">The claim to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> AddClaimAsync(TUser user, Claim claim);

        /// <summary>
        /// Adds the specified <paramref name="claims"/> to the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claims to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims);

        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim);

        /// <summary>
        /// Removes the specified <paramref name="claim"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claim"/> from.</param>
        /// <param name="claim">The <see cref="Claim"/> to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim);

        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims);

        /// <summary>
        /// Gets a list of <see cref="Claim"/>s to be belonging to the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose claims to retrieve.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.
        /// </returns>
        Task<IList<Claim>> GetClaimsAsync(TUser user);

        /// <summary>
        /// Gets the user, if any, associated with the normalized value of the specified email address.
        /// Note: Its recommended that identityOptions.User.RequireUniqueEmail be set to true when using this method, otherwise
        /// the store may throw if there are users with duplicate emails.
        /// </summary>
        /// <param name="email">The email address to return the user for.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user, if any, associated with a normalized value of the specified email address.
        /// </returns>
        Task<TUser?> FindByEmailAsync(string email);

        /// <summary>
        /// Verifies the specified two factor authentication <paramref name="token" /> against the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user the token is supposed to be for.</param>
        /// <param name="tokenProvider">The provider which will verify the token.</param>
        /// <param name="token">The token to verify.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, true if the token is valid,
        /// otherwise false.
        /// </returns>
        Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token);

        /// <summary>
        /// Gets a two factor authentication token for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user the token is for.</param>
        /// <param name="tokenProvider">The provider which will generate the token.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, a two factor authentication token
        /// for the user.
        /// </returns>
        Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider);

        /// <summary>
        /// Regenerates the security stamp for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose security stamp should be regenerated.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        /// <remarks>
        /// Regenerating a security stamp will sign out any saved login for the user.
        /// </remarks>
        Task<IdentityResult> UpdateSecurityStampAsync(TUser user);

        /// <summary>
        /// Returns the authenticator key for the user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>The authenticator key</returns>
        Task<string?> GetAuthenticatorKeyAsync(TUser user);

        /// <summary>
        /// Resets the authenticator key for the user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>Whether the user was successfully updated.</returns>
        Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user);

        /// <summary>
        /// Generates a password reset token for the specified <paramref name="user"/>, using
        /// the configured password reset token provider.
        /// </summary>
        /// <param name="user">The user to generate a password reset token for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation,
        /// containing a password reset token for the specified <paramref name="user"/>.</returns>
        Task<string?> GeneratePasswordResetTokenAsync(TUser user);

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be retrieved.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, true if the specified <paramref name="user "/>
        /// has two factor authentication enabled, otherwise false.
        /// </returns>
        Task<bool> GetTwoFactorEnabledAsync(TUser user);

        /// <summary>
        /// Gets a list of valid two factor token providers for the specified <paramref name="user"/>,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user the whose two factor authentication providers will be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, a list of two
        /// factor authentication providers for the specified user.
        /// </returns>
        Task<IList<string>> GetValidTwoFactorProvidersAsync(TUser user);

        /// <summary>
        /// Sets a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
        /// <param name="enabled">A flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, the <see cref="IdentityResult"/> of the operation
        /// </returns>
        Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled);

        /// <summary>
        /// Resets the <paramref name="user"/>'s password to the specified <paramref name="newPassword"/> after
        /// validating the given password reset <paramref name="token"/>.
        /// </summary>
        /// <param name="user">The user whose password should be reset.</param>
        /// <param name="token">The password reset token to verify.</param>
        /// <param name="newPassword">The new password to set if reset token verification succeeds.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword);

        /// <summary>
        /// Resets the access failed count for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose failed access count should be reset.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        Task<IdentityResult> ResetAccessFailedCountAsync(TUser user);

        /// <summary>
        /// Increments the access failed count for the user as an asynchronous operation.
        /// If the failed access account is greater than or equal to the configured maximum number of attempts,
        /// the user will be locked out for the configured lockout time span.
        /// </summary>
        /// <param name="user">The user whose failed access count to increment.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        Task<IdentityResult> AccessFailedAsync(TUser user);
    }
}
