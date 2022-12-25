using epicor.bll;
using epicor.entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.DirectoryServices.Protocols;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace epicor.api.API
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration configuration;
        ApiResponseManager apiResponseManager;
        ApiRespons apiResponse;

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("login")]
        public IActionResult Authenticate(LoginRequest loginRequest)
        {
            try
            {
                HttpResponseMessage responseMsg = new HttpResponseMessage();
                LoginResponse loginResponse = new LoginResponse();
                Authenticate auth = new Authenticate();
                loginResponse =auth.AuthenticateUser(loginRequest, this.configuration);
                if (loginResponse == null)
                {
                    apiResponse.ResponseMessage = "Invalid credentials";
                    return Ok(apiResponseManager.PrepareErrorRsponse(apiResponse));
                }

                //apiResponse.Data = loginResponse;
                // apiResponse = apiResponseManager.PrepareSuccessRsponse(apiResponse);
                return Ok(loginResponse);
                //return Ok(apiResponse.Data);
            }
            catch (Exception ex)
            {
               // Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
                apiResponse = apiResponseManager.PrepareErrorRsponse();
                return Ok(apiResponse);
            }
        }


    }
}
