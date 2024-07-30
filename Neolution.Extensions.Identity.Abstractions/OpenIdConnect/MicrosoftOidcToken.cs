namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    /// <summary>
    /// The OIDC token for logging in with Microsoft Accounts.
    /// </summary>
    /// <seealso cref="OpenIdConnectToken" />
    public class MicrosoftOidcToken : OpenIdConnectToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MicrosoftOidcToken"/> class.
        /// </summary>
        /// <param name="idToken">The ID token</param>
        public MicrosoftOidcToken(string idToken)
            : base(idToken)
        {
        }

        /// <inheritdoc />
        public override string DiscoveryDocumentUrl => "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";

        /// <inheritdoc />
        public override string ClientId => string.Empty;

        /// <inheritdoc />
        public override string Issuer => "https://accounts.google.com";
    }
}
