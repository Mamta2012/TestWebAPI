using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Configuration;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

  //  private readonly IConfiguration _configuration;
   // private IConfiguration Configuration;
    public class UserController : ControllerBase
    {
       // string _configuration = configuration.GetSection("connectionStrings").GetChildren().FirstOrDefault(config => config.Key == "Title").Value;

    }
}
