namespace Microsoft.Extensions.DependencyInjection
{
    using System.IdentityModel.Tokens.Jwt;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.DependencyInjection.Extensions;
    using Microsoft.Extensions.Options;
    using Neolution.Extensions.Identity;
    using Neolution.Extensions.Identity.Abstractions;
    using Neolution.Extensions.Identity.Abstractions.Options;

    /// <summary>
    /// Extension methods for services working with ASP.NET Core Identity.
    /// </summary>
    public static class IdentityExtensions
    {
        /// <summary>
        /// Adds the identity services.
        /// </summary>
        /// <typeparam name="TDbContext">The type of the database context.</typeparam>
        /// <typeparam name="TUserAccount">The type of the user account.</typeparam>
        /// <param name="services">The services.</param>
        public static void AddNeolutionIdentity<TDbContext, TUserAccount>(this IServiceCollection services)
            where TDbContext : DbContext
            where TUserAccount : IdentityUser<Guid>
        {
            services.AddIdentityCore<TUserAccount>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = false;
                })
                .AddEntityFrameworkStores<TDbContext>()
                .AddTokenProvider<DataProtectorTokenProvider<TUserAccount>>(TokenOptions.DefaultProvider)
                .AddTokenProvider<EmailTokenProvider<TUserAccount>>(TokenOptions.DefaultEmailProvider)
                .AddTokenProvider<PhoneNumberTokenProvider<TUserAccount>>(TokenOptions.DefaultPhoneProvider)
                .AddTokenProvider<AuthenticatorTokenProvider<TUserAccount>>(TokenOptions.DefaultAuthenticatorProvider);

            services.AddDataProtection();

            services.TryAddScoped<SignInManager<TUserAccount>>();

            services.AddOptions<NeolutionIdentityOptions>()
                .Configure<IConfiguration>((options, configuration) =>
                {
                    configuration.GetSection("NeolutionIdentity").Bind(options);
                });
            services.AddSingleton<IValidateOptions<NeolutionIdentityOptions>, NeolutionIdentityOptionsValidator>();

            services.Configure<IdentityOptions>(options =>
            {
                options.User.RequireUniqueEmail = true;
            });

            services.AddSingleton<IPasswordHasher<TUserAccount>, IdentityPasswordHasher<TUserAccount>>();
            services.AddScoped<IUserManager<TUserAccount>, UserManagerFacade<TUserAccount>>();
            services.AddScoped<ISignInManager<TUserAccount>, SignInManagerFacade<TUserAccount>>();
            services.AddScoped<ITokenSignInManager<TUserAccount>, TokenSignManager<TUserAccount>>();
        }

        /// <summary>
        /// By default, Microsoft has some legacy claim mapping that converts
        /// standard JWT claims into proprietary ones. This removes those mappings.
        /// </summary>
        /// <remarks>
        /// https://github.com/aspnet/Security/issues/1043
        /// https://github.com/dotnet/aspnetcore/issues/4660
        /// https://mderriey.com/2019/06/23/where-are-my-jwt-claims/
        /// </remarks>
        public static void RemoveLegacyClaimMappings()
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.Clear();
        }
    }
}
