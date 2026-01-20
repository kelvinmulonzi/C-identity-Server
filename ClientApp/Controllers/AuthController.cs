using Microsoft.AspNetCore.Mvc;
using ClientApp.Services;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Linq; // Added for Linq usage
using System.Net.Http;
using System.Text;
using System.Text.Json;

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
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            try
            {
                // This assumes a method for the ROPC (password) grant exists in your OAuth2Service.
                // You will need to implement this method in OAuth2Service.cs.
                var tokenResponse = await _oauth2Service.GetTokenWithPasswordAsync(username, password);

                if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.access_token))
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return View();
                }

                // Store tokens in session
                HttpContext.Session.SetString("access_token", tokenResponse.access_token);
                if (!string.IsNullOrEmpty(tokenResponse.refresh_token))
                {
                    HttpContext.Session.SetString("refresh_token", tokenResponse.refresh_token);
                }
                await HttpContext.Session.CommitAsync();

                // --- JWT DECODING AND CLAIMS EXTRACTION ---
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(tokenResponse.access_token);
                var name = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value 
                               ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value 
                               ?? "Unknown User";

                var email = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value 
                            ?? "Not available";
                
                // Prepare claims for the local cookie session
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, name), 
                    new Claim(ClaimTypes.Email, email),
                    new Claim("access_token", tokenResponse.access_token)
                };

                var claimsIdentity = new ClaimsIdentity(claims, 
                    CookieAuthenticationDefaults.AuthenticationScheme);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    new AuthenticationProperties { IsPersistent = true });

                Console.WriteLine($"[DEBUG] Login successful for {name}, redirecting to home");
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Login - Error: {ex.Message}");
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View();
            }
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string username, string email, string password)
        {
            var registerEndpoint = _configuration["OAuth2:RegisterEndpoint"];
            if (string.IsNullOrEmpty(registerEndpoint))
            {
                ModelState.AddModelError("", "Registration endpoint is not configured.");
                return View();
            }

            using var httpClient = new HttpClient();
            var registrationData = new
            {
                username,
                email,
                password
            };

            var response = await httpClient.PostAsync(registerEndpoint, new StringContent(JsonSerializer.Serialize(registrationData), Encoding.UTF8, "application/json"));

            if (response.IsSuccessStatusCode)
            {
                return RedirectToAction("Login");
            }

            var errorContent = await response.Content.ReadAsStringAsync();
            ModelState.AddModelError("", $"Registration failed: {errorContent}");
            return View();
        }

        [HttpGet]
        public IActionResult RedirectToAuth()
        {
            Console.WriteLine("[DEBUG] RedirectToAuth action started");
    
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

            // Validate state (rest of validation remains unchanged)
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || string.IsNullOrEmpty(storedState))
            {
                Console.WriteLine($"[DEBUG] Callback - Missing parameters. Code: {code}, State: {state}, StoredState: {storedState}");
                return RedirectToAction("Login"); // Start over
            }

            var stateParts = state.Split('.');
            var originalState = stateParts[0];
            var timestamp = stateParts.Length > 1 ? long.Parse(stateParts[1]) : 0;
            
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

                // --- START JWT DECODING AND CLAIMS EXTRACTION ---
                
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(tokenResponse.access_token) as JwtSecurityToken;

                if (jwtToken == null)
                {
                    return BadRequest("Invalid access token received.");
                }
                
                // Extract key claims: Name/Username and Email (or Id)
                var username = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value 
                               ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value 
                               ?? "Unknown User";

                var email = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value 
                            ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value 
                            ?? "Not available";
                
                // --- END JWT DECODING AND CLAIMS EXTRACTION ---

                // Prepare claims for the local cookie session
                var claims = new List<Claim>
                {
                    // Use the extracted username for the primary identity claim
                    new Claim(ClaimTypes.Name, username), 
                    new Claim(ClaimTypes.Email, email),
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

                Console.WriteLine($"[DEBUG] Callback - Authentication successful as {username}, redirecting to home");
                return RedirectToAction("Index", "Home"); // <--- Verified: The return statement is here.
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


        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();
            return RedirectToAction("Index", "Home");
        }
    }
}