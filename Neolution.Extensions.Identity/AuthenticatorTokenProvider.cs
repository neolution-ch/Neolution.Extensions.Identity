﻿namespace Neolution.Extensions.Identity
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// TokenProvider that generates tokens from the user's security stamp and notifies a user via email.
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    public class AuthenticatorTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
        where TUser : class
    {
        /// <summary>
        /// Checks if a two-factor authentication token can be generated for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two-factor authentication token.</param>
        /// <returns>True if the user has an email address set, otherwise false.</returns>
        public override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }

            return CanGenerateTwoFactorTokenInternalAsync(manager, user);
        }

        /// <summary>
        /// Returns the a value for the user used as entropy in the generated token.
        /// </summary>
        /// <param name="purpose">The purpose of the two-factor authentication token.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two-factor authentication token.</param>
        /// <returns>A string suitable for use as entropy in token generation.</returns>
        public override Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }

            return GetUserModifierInternalAsync(purpose, manager, user);
        }

        /// <summary>
        /// Checks if a two-factor authentication token can be generated for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two-factor authentication token.</param>
        /// <returns>True if the user has an email address set, otherwise false.</returns>
        private static async Task<bool> CanGenerateTwoFactorTokenInternalAsync(UserManager<TUser> manager, TUser user)
        {
            var email = await manager.GetEmailAsync(user).ConfigureAwait(false);

            return !string.IsNullOrWhiteSpace(email) && await manager.IsEmailConfirmedAsync(user).ConfigureAwait(false);
        }

        /// <summary>
        /// Returns the a value for the user used as entropy in the generated token.
        /// </summary>
        /// <param name="purpose">The purpose of the two-factor authentication token.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two-factor authentication token.</param>
        /// <returns>A string suitable for use as entropy in token generation.</returns>
        private static async Task<string> GetUserModifierInternalAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            var email = await manager.GetEmailAsync(user).ConfigureAwait(false);

            return $"Authenticator:{purpose}:{email}";
        }
    }
}
