using Microsoft.AspNetCore.Mvc;
using ClientApp.Services;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

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
            Console.WriteLine("[DEBUG] Login action started");
    
            // If we already have tokens, just redirect to home
            if (!string.IsNullOrEmpty(HttpContext.Session.GetString("access_token")))
            {
                Console.WriteLine("[DEBUG] User already has access token, redirecting to home");
                return RedirectToAction("Index", "Home");
            }

            var authorizationEndpoint = _configuration["OAuth2:AuthorizationEndpoint"]!;
            var clientId = _configuration["OAuth2:ClientId"]!;
            var redirectUri = _configuration["OAuth2:RedirectUri"]!;
            var scope = "read write";

            Console.WriteLine($"[DEBUG] Authorization Endpoint: {authorizationEndpoint}");
            Console.WriteLine($"[DEBUG] Client ID: {clientId}");
            Console.WriteLine($"[DEBUG] Redirect URI: {redirectUri}");

            // Only generate a new state if we don't have one already
            var state = HttpContext.Session.GetString("oauth_state") ?? Guid.NewGuid().ToString();
            HttpContext.Session.SetString("oauth_state", state);

            // Add a timestamp to prevent CSRF
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            state = $"{state}.{timestamp}";

            Console.WriteLine($"[DEBUG] Generated state: {state}");

            var authUrl = $"{authorizationEndpoint}?client_id={clientId}" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString(scope)}" +
                          $"&state={state}";

            Console.WriteLine($"[DEBUG] Redirecting to: {authUrl}");
            return Redirect(authUrl);
        }
[HttpGet]
public async Task<IActionResult> Callback(string code, string state)
{
    Console.WriteLine($"[DEBUG] Callback - Starting with code: {code}, state: {state}");
    
    // Get the state from session before doing anything else
    var storedState = HttpContext.Session.GetString("oauth_state");
    Console.WriteLine($"[DEBUG] Callback - Stored state: {storedState}");

    // Clear the state immediately after retrieving it
    if (!string.IsNullOrEmpty(storedState))
    {
        HttpContext.Session.Remove("oauth_state");
        await HttpContext.Session.CommitAsync();
    }

    // If we already have tokens, just redirect to home
    if (!string.IsNullOrEmpty(HttpContext.Session.GetString("access_token")))
    {
        Console.WriteLine($"[DEBUG] Callback - Already authenticated, redirecting to home");
        return RedirectToAction("Index", "Home");
    }

    // Validate state
    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || string.IsNullOrEmpty(storedState))
    {
        Console.WriteLine($"[DEBUG] Callback - Missing parameters. Code: {code}, State: {state}, StoredState: {storedState}");
        return RedirectToAction("Login"); // Start over
    }

    // Split the state into original state and timestamp
    var stateParts = state.Split('.');
    var originalState = stateParts[0];
    var timestamp = stateParts.Length > 1 ? long.Parse(stateParts[1]) : 0;
    
    // Verify state matches and is not too old (5 minutes)
    if (originalState != storedState || 
        (DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp) > 300)
    {
        Console.WriteLine($"[DEBUG] Callback - Invalid or expired state");
        return RedirectToAction("Login"); // Start over
    }

    try
    {
        var redirectUri = _configuration["OAuth2:RedirectUri"]!;
        Console.WriteLine($"[DEBUG] Callback - Exchanging code for token");
        
        var tokenResponse = await _oauth2Service.ExchangeCodeForToken(code, redirectUri);
        
        // Store tokens in session
        HttpContext.Session.SetString("access_token", tokenResponse.access_token);
        HttpContext.Session.SetString("refresh_token", tokenResponse.refresh_token);
        await HttpContext.Session.CommitAsync();
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "testuser"), // You can get this from the token if available
            new Claim("access_token", tokenResponse.access_token)
        };

        var claimsIdentity = new ClaimsIdentity(claims, 
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
            });

        Console.WriteLine($"[DEBUG] Callback - Authentication successful, redirecting to home");
        return RedirectToAction("Index", "Home");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DEBUG] Callback - Error: {ex.Message}");
        return BadRequest($"Authentication failed: {ex.Message}");
    }
}
[HttpGet("test-session")]
public IActionResult TestSession()
{
    var sessionId = HttpContext.Session.Id;
    var testValue = HttpContext.Session.GetString("test_key") ?? "No value set";
    HttpContext.Session.SetString("test_key", "Test value set at " + DateTime.Now);
    return Content($"Session ID: {sessionId}\nTest Value: {testValue}");
}


[HttpPost]
public async Task<IActionResult> Logout()
{
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    HttpContext.Session.Clear();
    return RedirectToAction("Index", "Home");
}
    }
}