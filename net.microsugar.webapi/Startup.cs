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
            // �N�������ҪA�ȲK�[��DI
            //����(Authentication)�N�O���t�λ{�o�A�O��
            //���v(Authorization)���t�ΧP�_�A�O�_���v��
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

                    options.GetClaimsFromUserInfoEndpoint = true; // �� UserInfo Endpoint ���o�Τ���(�]�tRole)
                    options.ClaimActions.MapJsonKey("role", "role", "role"); // for [Authorize(Roles= "AdminRole")] �ݭn
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
            app.UseAuthorization(); // �K�[�F���v������A�H�T�O�ΦW�Ȥ�ݵL�k�X�ݧڭ̪�API���I

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
