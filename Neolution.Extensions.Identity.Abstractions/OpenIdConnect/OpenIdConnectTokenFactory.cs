namespace Neolution.Extensions.Identity.Abstractions.OpenIdConnect
{
    using Microsoft.Extensions.Options;
    using Neolution.Extensions.Identity.Abstractions.Options;

    /// <inheritdoc />
    public class OpenIdConnectTokenFactory : IOpenIdConnectTokenFactory
    {
        /// <summary>
        /// The Identity options
        /// </summary>
        private readonly NeolutionIdentityOptions options;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectTokenFactory"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <exception cref="System.ArgumentNullException">options</exception>
        public OpenIdConnectTokenFactory(IOptions<NeolutionIdentityOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.options = options.Value;
        }

        /// <inheritdoc />
        public OpenIdConnectToken GoogleToken(string idToken)
        {
            if (this.options.Google is null)
            {
                throw new InvalidOperationException("Missing configuration to handle Google OIDC tokens. Make sure you have configured the 'Google' section inside the 'NeolutionIdentity' section in your app settings.");
            }

            if (string.IsNullOrWhiteSpace(this.options.Google.ClientId))
            {
                throw new InvalidOperationException("Missing Google Client ID from configuration or the value was empty");
            }

            var validationOptions = new OpenIdConnectTokenValidationOptions
            {
                DiscoveryDocumentUrl = "https://accounts.google.com/.well-known/openid-configuration",
                Issuer = "https://accounts.google.com",
                ClientId = this.options.Google.ClientId,
            };

            return new OpenIdConnectToken(idToken, validationOptions);
        }

        /// <inheritdoc />
        public OpenIdConnectToken MicrosoftToken(string idToken, string tenantId)
        {
            // TODO: Incomplete configuration
            var validationOptions = new OpenIdConnectTokenValidationOptions
            {
                DiscoveryDocumentUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
                Issuer = $"https://login.microsoftonline.com/common/v2.0/{tenantId}",
                ClientId = "tbd",
            };

            return new OpenIdConnectToken(idToken, validationOptions);
        }
    }
}
