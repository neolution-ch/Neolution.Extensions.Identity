namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    /// <summary>
    /// The OIDC token for logging in with Google Accounts.
    /// </summary>
    /// <seealso cref="OpenIdConnectToken" />
    public class GoogleToken : OpenIdConnectToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GoogleToken"/> class.
        /// </summary>
        /// <param name="idToken">The ID token.</param>
        public GoogleToken(string idToken)
            : base(idToken)
        {
        }

        /// <inheritdoc />
        public override string DiscoveryDocumentUrl => "https://accounts.google.com/.well-known/openid-configuration";

        /// <inheritdoc />
        public override string ClientId => string.Empty;

        /// <inheritdoc />
        public override string Issuer => "https://accounts.google.com";
    }
}
