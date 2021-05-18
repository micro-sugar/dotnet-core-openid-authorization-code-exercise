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
            // 將身份驗證服務添加到DI
            // 驗證(Authentication)就是讓系統認得你是誰
            // 授權(Authorization)讓系統判斷你是否有權限
            // [同時接受cookie及jwt](https://stackoverflow.com/questions/46938248/asp-net-core-2-0-combining-cookies-and-bearer-authorization-for-the-same-endpoin#55627054)
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
                    ValidateIssuer = true, // 驗證簽發者
                    ValidateAudience = true, // 驗證 Audience (Token接收方)
                    ValidateLifetime = true, // 驗證 Token 有效期間
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

                options.GetClaimsFromUserInfoEndpoint = true; // 由 UserInfo Endpoint 取得用戶資料(包含Role)
                options.ClaimActions.MapJsonKey("role", "role", "role"); // for [Authorize(Roles= "tRole")] 需要

                options.UseTokenLifetime = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };

                options.SaveTokens = true;
                options.ResponseType = OpenIdConnectResponseType.Code;

#if DEBUG
                // 接受 Authority 使用非Https
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

            // 加上驗證/授權的 middleware
            app.UseAuthentication(); // 將身份驗證中間件添加到管道中，以便對主機的每次調用都將自動執行身份驗證
            app.Use(async (context, next) => // 將未經授權的用戶重定向到登錄頁面
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
            app.UseAuthorization(); // 添加了授權中間件，以確保匿名客戶端無法訪問我們的API端點

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers()
                    .RequireAuthorization("WebpageCheckPolicy")
                    ;
            });
        }
    }
}
