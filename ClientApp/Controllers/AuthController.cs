using Microsoft.AspNetCore.Mvc;
using ClientApp.Services;

namespace ClientApp.Controllers
{
    public class AuthController : Controller
    {
        private readonly OAuth2Service _oauth2Service;
        private readonly IConfiguration _configuration;

        public AuthController(OAuth2Service oauth2Service, IConfiguration configuration)
        {
            _oauth2Service = oauth2Service;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Login()
        {
            var authorizationEndpoint = _configuration["OAuth2:AuthorizationEndpoint"]!;
            var clientId = _configuration["OAuth2:ClientId"]!;
            var redirectUri = _configuration["OAuth2:RedirectUri"]!;
            var scope = "read write";
            var state = Guid.NewGuid().ToString();

            // Store state for validation
            HttpContext.Session.SetString("oauth_state", state);

            var authUrl = $"{authorizationEndpoint}?client_id={clientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope={Uri.EscapeDataString(scope)}&state={state}";

            return Redirect(authUrl);
        }

        [HttpGet]
        public async Task<IActionResult> Callback(string code, string state)
        {
            var storedState = HttpContext.Session.GetString("oauth_state");
            if (state != storedState)
            {
                return BadRequest("Invalid state parameter");
            }

            try
            {
                var redirectUri = _configuration["OAuth2:RedirectUri"]!;
                var tokenResponse = await _oauth2Service.ExchangeCodeForToken(code, redirectUri);

                // Store tokens in session (in production, use secure storage)
                HttpContext.Session.SetString("access_token", tokenResponse.access_token);
                HttpContext.Session.SetString("refresh_token", tokenResponse.refresh_token);

                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }

        [HttpPost]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index", "Home");
        }
    }
}