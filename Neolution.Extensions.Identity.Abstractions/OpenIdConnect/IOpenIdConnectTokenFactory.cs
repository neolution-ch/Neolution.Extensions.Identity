namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    /// <summary>
    /// The OpenID Connect token factory.
    /// </summary>
    public interface IOpenIdConnectTokenFactory
    {
        /// <summary>
        /// Create the Google-specific OpenID token.
        /// </summary>
        /// <param name="idToken">The identifier token.</param>
        /// <returns>The <see cref="OpenIdConnectToken"/>.</returns>
        OpenIdConnectToken GoogleToken(string idToken);

        /// <summary>
        /// Create the Microsoft-specific OpenID token.
        /// </summary>
        /// <param name="idToken">The identifier token.</param>
        /// <param name="tenantId">The tenant identifier.</param>
        /// <returns>The <see cref="OpenIdConnectToken"/>.</returns>
        OpenIdConnectToken MicrosoftToken(string idToken, string tenantId);
    }
}
