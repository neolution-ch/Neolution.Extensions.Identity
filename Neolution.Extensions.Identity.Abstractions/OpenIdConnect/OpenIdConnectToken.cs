namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    /// <summary>
    /// The OpenID Connect token.
    /// </summary>
    public class OpenIdConnectToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectToken" /> class.
        /// </summary>
        /// <param name="idToken">The ID token.</param>
        /// <param name="options">The validation options.</param>
        public OpenIdConnectToken(string idToken, OpenIdConnectTokenValidationOptions options)
        {
            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new ArgumentException("ID token must not be null or empty", nameof(idToken));
            }

            this.ValidationOptions = options;
            this.IdToken = idToken;
        }

        /// <summary>
        /// Gets the validation options.
        /// </summary>
        public OpenIdConnectTokenValidationOptions ValidationOptions { get; }

        /// <summary>
        /// Gets the ID token.
        /// </summary>
        public string IdToken { get; }
    }
}
