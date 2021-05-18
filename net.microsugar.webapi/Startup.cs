using IdentityModel.AspNetCore.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace net.microsugar.webapi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            // �N�������ҪA�ȲK�[��DI
            // ����(Authentication)�N�O���t�λ{�o�A�O��
            // ���v(Authorization)���t�ΧP�_�A�O�_���v��
            // [�P�ɱ���cookie��jwt](https://stackoverflow.com/questions/46938248/asp-net-core-2-0-combining-cookies-and-bearer-authorization-for-the-same-endpoin#55627054)
            services.AddAuthentication(options =>
            {
                //options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultScheme = "smart";
            })
            .AddPolicyScheme("smart", "Cookie or Jwt", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    var bearerAuth = context.Request.Headers["Authorization"].FirstOrDefault()?.StartsWith("Bearer ") ?? false;
                    // You could also check for the actual path here if that's your requirement:
                    // eg: if (context.HttpContext.Request.Path.StartsWithSegments("/api", StringComparison.InvariantCulture))
                    if (bearerAuth)
                        return JwtBearerDefaults.AuthenticationScheme;
                    else
                        return CookieAuthenticationDefaults.AuthenticationScheme;
                };
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.Authority = Configuration["auth:oidc:AuthBaseUri"];
                options.Audience = Configuration["auth:oidc:Scopes"];

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true, // ����ñ�o��
                    ValidateAudience = true, // ���� Audience (Token������)
                    ValidateLifetime = true, // ���� Token ���Ĵ���
                    ValidateIssuerSigningKey = true,
                    NameClaimType = "name",
                    RoleClaimType = "role",
                };
                options.SaveToken = true;
                options.ForwardSignIn = OpenIdConnectDefaults.AuthenticationScheme;
                options.ForwardSignOut = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                // https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.openidconnect.openidconnectoptions?view=aspnetcore-3.1

                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;

                options.Authority = Configuration["auth:oidc:AuthBaseUri"];
                options.ClientId = Configuration["auth:oidc:ClientId"];
                options.ClientSecret = Configuration["auth:oidc:ClientSecret"];
                options.UsePkce = true;

                // The "offline_access" scope is needed to get a refresh token
                options.Scope.Clear();
                options.Scope.Add("openid roles profile");
                options.Scope.Add(Configuration["auth:oidc:Scopes"]);

                options.GetClaimsFromUserInfoEndpoint = true; // �� UserInfo Endpoint ���o�Τ���(�]�tRole)
                options.ClaimActions.MapJsonKey("role", "role", "role"); // for [Authorize(Roles= "tRole")] �ݭn

                options.UseTokenLifetime = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };

                options.SaveTokens = true;
                options.ResponseType = OpenIdConnectResponseType.Code;

#if DEBUG
                // ���� Authority �ϥΫDHttps
                options.RequireHttpsMetadata = false;
#endif
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("WebpageCheckPolicy", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    // https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes?view=net-5.0
                    policy.RequireClaim(ClaimTypes.Webpage, "https://localhost:5001");
                });

                options.AddPolicy("tRolePolicy", policy =>
                {
                    policy.RequireAuthenticatedUser();
                    // https://docs.microsoft.com/en-us/dotnet/api/system.security.claims.claimtypes?view=net-5.0
                    policy.RequireClaim(ClaimTypes.Role, "tRole");
                });

                var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(CookieAuthenticationDefaults.AuthenticationScheme, JwtBearerDefaults.AuthenticationScheme);
                defaultAuthorizationPolicyBuilder = defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();

                options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            // �[�W����/���v�� middleware
            app.UseAuthentication(); // �N�������Ҥ�����K�[��޹D���A�H�K��D�����C���եγ��N�۰ʰ��樭������
            app.Use(async (context, next) => // �N���g���v���Τ᭫�w�V��n������
            {
                await next();
                var bearerAuth = context.Request.Headers["Authorization"]
                    .FirstOrDefault()?.StartsWith("Bearer ") ?? false;
                if (context.Response.StatusCode == 401
                    && !context.User.Identity.IsAuthenticated
                    && !bearerAuth)
                {
                    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);
                }
            });
            app.UseAuthorization(); // �K�[�F���v������A�H�T�O�ΦW�Ȥ�ݵL�k�X�ݧڭ̪�API���I

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers()
                    .RequireAuthorization("WebpageCheckPolicy")
                    ;
            });
        }
    }
}
