namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    /// <summary>
    /// The OpenID Connect token.
    /// </summary>
    public abstract class OpenIdConnectToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectToken"/> class.
        /// </summary>
        /// <param name="idToken">The ID token.</param>
        protected OpenIdConnectToken(string idToken)
        {
            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new ArgumentException("ID token must not be null or whitespace.", nameof(idToken));
            }

            this.IdToken = idToken;
        }

        /// <summary>
        /// Gets or sets the ID token.
        /// </summary>
        public string IdToken { get; protected set; }

        /// <summary>
        /// Gets the client identifier.
        /// </summary>
        public abstract string ClientId { get; }

        /// <summary>
        /// Gets the discovery document URL.
        /// </summary>
        public abstract string DiscoveryDocumentUrl { get; }

        /// <summary>
        /// Gets the issuer.
        /// </summary>
        public abstract string Issuer { get; }
    }
}
