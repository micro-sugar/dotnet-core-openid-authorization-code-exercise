using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
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
            //驗證(Authentication)就是讓系統認得你是誰
            //授權(Authorization)讓系統判斷你是否有權限
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    // https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.openidconnect.openidconnectoptions?view=aspnetcore-3.1

                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    options.Authority = Configuration["auth:oidc:AuthBaseUri"];
                    options.ClientId = Configuration["auth:oidc:ClientId"];

                    // The "offline_access" scope is needed to get a refresh token
                    options.Scope.Clear();
                    //options.Scope.Add("openid roles profile");
                    options.Scope.Add(Configuration["auth:oidc:Scopes"]);

                    options.GetClaimsFromUserInfoEndpoint = true; // 由 UserInfo Endpoint 取得用戶資料(包含Role)
                    options.ClaimActions.MapJsonKey("role", "role", "role"); // for [Authorize(Roles= "AdminRole")] 需要
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
            app.UseAuthorization(); // 添加了授權中間件，以確保匿名客戶端無法訪問我們的API端點

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
