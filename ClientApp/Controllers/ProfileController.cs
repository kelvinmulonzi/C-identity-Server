using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ClientApp.Services;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace ClientApp.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly OAuth2Service _oauth2Service;
        private readonly IConfiguration _configuration;

        public ProfileController(OAuth2Service oauth2Service, IConfiguration configuration)
        {
            _oauth2Service = oauth2Service;
            _configuration = configuration;
        }

        public async Task<IActionResult> Index()
        {
            try
            {
                // The [Authorize] attribute ensures the user is authenticated.
                // Claims are populated from the id_token and/or the UserInfo endpoint.
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var userName = User.FindFirst(ClaimTypes.Name)?.Value;
                var email = User.FindFirst(ClaimTypes.Email)?.Value;

                // If you have a user info endpoint in your resource server, you can fetch additional data
                // var accessToken = await HttpContext.GetTokenAsync("access_token");
                // var userInfo = await _oauth2Service.CallProtectedResource(
                //     accessToken, 
                //     $"{_configuration["OAuth2:ResourceServer"]}/api/user/{userId}");
                
                // For now, we'll just use the claims from the token
                var userProfile = new
                {
                    UserId = userId,
                    UserName = userName,
                    Email = email,
                    // Add any additional profile fields here
                    // You can map them from the token claims or fetch from the resource server
                };

                return View(userProfile);
            }
            catch (Exception ex)
            {
                // Log the error
                ModelState.AddModelError("", $"Error loading profile: {ex.Message}");
                return View();
            }
        }
    }
}
