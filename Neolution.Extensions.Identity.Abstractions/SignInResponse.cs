namespace Neolution.Extensions.Identity.Abstractions
{
    public class SignInResponse
    {
        public bool Succeeded { get; protected set; }

        public bool IsLockedOut { get; protected set; }

        public bool IsNotAllowed { get; protected set; }

        public bool RequiresTwoFactor { get; protected set; }

        public static SignInResponse Success => new() { Succeeded = true };

        public static SignInResponse Lockout => new() { IsLockedOut = true };

        public static SignInResponse NotAllowed => new() { IsNotAllowed = true };

        public static SignInResponse TwoFactorRequired => new() { RequiresTwoFactor = true };

        public static SignInResponse Failed => new();
    }
}
