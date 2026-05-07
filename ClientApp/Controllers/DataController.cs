 using Microsoft.AspNetCore.Mvc;
using ClientApp.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace ClientApp.Controllers
{
    [Authorize] // Require authentication for this controller
    public class DataController : Controller
    {
        private readonly OAuth2Service _oauth2Service;
        private readonly IConfiguration _configuration;

        public DataController(OAuth2Service oauth2Service, IConfiguration configuration)
        {
            _oauth2Service = oauth2Service;
            _configuration = configuration;
        }

        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            try
            {
                // Get the access token from the authentication cookie
                var accessToken = await HttpContext.GetTokenAsync("access_token");
                var resourceUrl = _configuration["OAuth2:ResourceServer"] + "/api/user/profile";
                var result = await _oauth2Service.CallProtectedResource(accessToken!, resourceUrl);
                
                ViewBag.ApiResponse = result;
                return View();
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                return View();
            }
        }
    }
}