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
            // If we already have tokens, just redirect to home
            if (!string.IsNullOrEmpty(HttpContext.Session.GetString("access_token")))
            {
                return RedirectToAction("Index", "Home");
            }

            var authorizationEndpoint = _configuration["OAuth2:AuthorizationEndpoint"]!;
            var clientId = _configuration["OAuth2:ClientId"]!;
            var redirectUri = _configuration["OAuth2:RedirectUri"]!;
            var scope = "read write";
    
            // Only generate a new state if we don't have one already
            var state = HttpContext.Session.GetString("oauth_state") ?? Guid.NewGuid().ToString();
            HttpContext.Session.SetString("oauth_state", state);
    
            // Add a timestamp to prevent CSRF
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            state = $"{state}.{timestamp}";
    
            Console.WriteLine($"[DEBUG] Login - New state: {state}");
            Console.WriteLine($"[DEBUG] Session ID: {HttpContext.Session.Id}");

            var authUrl = $"{authorizationEndpoint}?client_id={clientId}" +
                          $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                          $"&response_type=code" +
                          $"&scope={Uri.EscapeDataString(scope)}" +
                          $"&state={state}";

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

        Console.WriteLine($"[DEBUG] Callback - Authentication successful, redirecting to home");
        return RedirectToAction("Index", "Home");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DEBUG] Callback - Error: {ex.Message}");
        return BadRequest($"Authentication failed: {ex.Message}");
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