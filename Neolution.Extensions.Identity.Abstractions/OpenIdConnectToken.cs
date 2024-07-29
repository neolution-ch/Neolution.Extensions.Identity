namespace Neolution.Extensions.Identity.Abstractions
{
    using System.Security.Claims;
    using Microsoft.IdentityModel.Tokens;

    public abstract class OpenIdConnectToken
    {
        public string IdToken { get; protected set; }

        public abstract string ClientId { get; }

        public abstract string DiscoveryDocumentUrl { get; }

        public abstract string Issuer { get; }

        protected OpenIdConnectToken(string idToken)
        {
            if (string.IsNullOrWhiteSpace(idToken))
            {
                throw new ArgumentException("ID token must not be null or whitespace.", nameof(idToken));
            }

            this.IdToken = idToken;
        }
    }

    public class GoogleToken : OpenIdConnectToken
    {
        public GoogleToken(string token)
            : base(token)
        {
        }

        public override string DiscoveryDocumentUrl => "https://accounts.google.com/.well-known/openid-configuration";

        public override string ClientId => "";

        public override string Issuer => "https://accounts.google.com";
    }

    public class MicrosoftOidcToken : OpenIdConnectToken
    {
        public MicrosoftOidcToken(string token)
            : base(token)
        {
        }

        public override string DiscoveryDocumentUrl => "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";

        public override string ClientId => "";

        public override string Issuer => "https://accounts.google.com";
    }
}
