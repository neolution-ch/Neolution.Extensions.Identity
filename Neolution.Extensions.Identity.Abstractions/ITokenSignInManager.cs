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
        /// <returns>The JWT if signed in; otherwise <c>null</c>.</returns>
        Task<JsonWebToken?> PasswordSignInAsync(string email, string password);

        /// <summary>
        /// Validates the sign in code from an authenticator app and creates and signs in the user, as an asynchronous operation.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="code">The two-factor authentication code to validate.</param>
        /// <param name="authenticationMethod">The method used to authenticate the user.</param>
        /// <returns>
        /// The task object representing the asynchronous operation containing the <see name="SignInResult" />
        /// for the sign-in attempt.
        /// </returns>
        Task<JsonWebToken?> TwoFactorAuthenticatorSignInAsync(Guid userId, string code, string authenticationMethod);

        /// <summary>
        /// Sign-in with generic OpenId Connect token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>The user if signed in; otherwise <c>null</c>.</returns>
        Task<TUser?> OpenIdConnectSignInAsync(OpenIdConnectToken token);

        /// <summary>
        /// Creates a JSON Web Token (JWT) for the specified user.
        /// </summary>
        /// <param name="user">The user for whom the token is being created.</param>
        /// <param name="amr"> The JWT authentication method reference (AMR). The allowed values can be found here: https://www.rfc-editor.org/rfc/rfc8176.html#section-2</param>
        /// <param name="authenticationMethod">The method used to authenticate the user.</param>
        /// <returns>The JWT if signed in; otherwise <c>null</c>.</returns>
        Task<JsonWebToken?> CreateAccessTokenAsync(TUser user, string amr, string authenticationMethod);
    }
}
