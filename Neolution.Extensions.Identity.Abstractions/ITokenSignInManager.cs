namespace Neolution.Extensions.Identity.Abstractions
{
    using Microsoft.AspNetCore.Identity;
    using Neolution.Extensions.Identity.Abstractions.OpenIdConnect;

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
        /// <param name="email">The user email address.</param>
        /// <param name="password">The password.</param>
        /// <returns>The JWT if signed-in; otherwise <c>null</c>.</returns>
        Task<JsonWebToken?> PasswordSignInAsync(string email, string password);

        /// <summary>
        /// Validates the sign in code from an authenticator app and creates and signs in the user, as an asynchronous operation.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="code">The two factor authentication code to validate.</param>
        /// <param name="authenticationMethod">The authentication method, if external authentication was used.</param>
        /// <returns>
        /// The task object representing the asynchronous operation containing the <see name="SignInResult" />
        /// for the sign-in attempt.
        /// </returns>
        Task<JsonWebToken?> TwoFactorAuthenticatorSignInAsync(Guid userId, string code, string? authenticationMethod);

        /// <summary>
        /// Sign-in with generic OpenId Connect token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>The user if signed in; otherwise <c>null</c>.</returns>
        Task<TUser?> OpenIdConnectSignInAsync(OpenIdConnectToken token);

        /// <summary>
        /// Creates the access token.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="authenticationMethod">The authentication method.</param>
        /// <returns>The JWT if signed in; otherwise <c>null</c>.</returns>
        Task<JsonWebToken?> CreateAccessTokenAsync(TUser user, string? authenticationMethod);
    }
}
