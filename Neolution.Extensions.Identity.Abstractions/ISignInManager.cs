namespace Neolution.Extensions.Identity.Abstractions
{
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// Provides the APIs for user sign in.
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface ISignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// Attempts to sign in the specified <paramref name="user"/> and <paramref name="password"/> combination
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to sign in.</param>
        /// <param name="password">The password to attempt to sign in with.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="lockoutOnFailure">Flag indicating if the user account should be locked if the sign in fails.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResponse"/>
        /// for the sign-in attempt.</returns>
        Task<SignInResponse> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure);

        /// <summary>
        /// Signs in a user via a previously registered third party login, as an asynchronous operation.
        /// </summary>
        /// <param name="loginProvider">The login provider to use.</param>
        /// <param name="providerKey">The unique provider identifier for the user.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResponse"/>
        /// for the sign-in attempt.</returns>
        Task<SignInResponse> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent);

        /// <summary>
        /// Signs in a user via a previously registered third party login, as an asynchronous operation.
        /// </summary>
        /// <param name="loginProvider">The login provider to use.</param>
        /// <param name="providerKey">The unique provider identifier for the user.</param>
        /// <param name="isPersistent">Flag indicating whether the sign-in cookie should persist after the browser is closed.</param>
        /// <param name="bypassTwoFactor">Flag indicating whether to bypass two factor authentication.</param>
        /// <returns>The task object representing the asynchronous operation containing the <see name="SignInResponse"/>
        /// for the sign-in attempt.</returns>
        Task<SignInResponse> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor);
    }
}
