namespace Neolution.Extensions.Identity.Abstractions
{
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// SignInManager that produces Json Web Tokens
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public interface IJwtSignInManager<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// Signs in via Google token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <returns>The <see cref="JsonWebToken"/>.</returns>
        Task<JsonWebToken?> SignInWithGoogleAsync(string token, string clientId);

        /// <summary>
        /// Signs in via password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="JsonWebToken"/>.</returns>
        Task<JsonWebToken?> PasswordSignInAsync(TUser user, string password);
    }
}
