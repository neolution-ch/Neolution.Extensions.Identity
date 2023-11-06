namespace Neolution.Extensions.Identity.Abstractions
{
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// The token-based "SignInManager".
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public interface ITokenSignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// Sign-in with a password.
        /// </summary>
        /// <param name="username">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The user if signed-in; otherwise <c>null</c>.</returns>
        Task<TUser?> PasswordSignInAsync(string username, string password);

        /// <summary>
        /// Sign-in with Google ID token.
        /// </summary>
        /// <param name="token">The ID token.</param>
        /// <returns>The user if signed-in; otherwise <c>null</c>.</returns>
        Task<TUser?> GoogleSignInAsync(string token);

        /// <summary>
        /// Creates the access token.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>The JWT if signed-in; otherwise <c>null</c>.</returns>
        Task<JsonWebToken?> CreateAccessTokenAsync(TUser user);

        /// <summary>
        /// Creates the access token.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="authenticationMethod">The authentication method.</param>
        /// <returns>The JWT if signed-in; otherwise <c>null</c>.</returns>
        Task<JsonWebToken?> CreateAccessTokenAsync(TUser user, string? authenticationMethod);
    }
}
