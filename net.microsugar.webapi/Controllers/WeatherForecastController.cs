using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace net.microsugar.webapi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        //[Authorize]
        [Authorize(Roles = "tRole")]
        public IEnumerable<WeatherForecast> Get()
        {
            try
            {
                var user = this.User;

                var userId = this.User.Identities.FirstOrDefault().Claims.ToList().Where(n => n.Type == ClaimTypes.NameIdentifier).FirstOrDefault();

                var access_token = this.HttpContext.GetTokenAsync("access_token");
                var id_token = this.HttpContext.GetTokenAsync("id_token");
                var refresh_token = this.HttpContext.GetTokenAsync("refresh_token");
            }
            catch (Exception)
            {
            }
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}
