namespace Neolution.Extensions.Identity.Abstractions
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Identity;

    /// <summary>
    /// The JWT generator.
    /// </summary>
    /// <typeparam name="TUser">The type of the user account.</typeparam>
    public interface IJwtGenerator<TUser>
        where TUser : IdentityUser<Guid>
    {
        /// <summary>
        /// Generates the access token.
        /// </summary>
        /// <param name="user">The user account.</param>
        /// <param name="userClaims">The user claims.</param>
        /// <returns>
        /// The JSON web token
        /// </returns>
        JsonWebToken GenerateAccessToken(TUser user, IEnumerable<Claim> userClaims);

        /// <summary>
        /// Generates the access token.
        /// </summary>
        /// <param name="user">The user account.</param>
        /// <param name="userClaims">The user claims.</param>
        /// <param name="amr">The Authentication Method Reference value.</param>
        /// <returns>
        /// The JSON web token
        /// </returns>
        JsonWebToken GenerateAccessToken(TUser user, IEnumerable<Claim> userClaims, string amr);
    }
}
