using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using AuthorizationServer.Services;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    [Route("oauth")]
    public class OAuth2Controller : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenService _tokenService;

        public OAuth2Controller(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            ITokenService tokenService)
        {
            _context = context;
            _userManager = userManager;
            _tokenService = tokenService;
        }

        [Authorize]
        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize(
            [FromQuery] string client_id,
            [FromQuery] string redirect_uri,
            [FromQuery] string response_type,
            [FromQuery] string scope,
            [FromQuery] string state,
            [FromQuery] string? nonce = null)
        {
            // Validate client
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == client_id && c.IsActive);
            
            if (client == null)
            {
                Console.WriteLine($"[DEBUG] Client not found. ClientId: {client_id}");
                return BadRequest("Invalid client");
            }

            if (client.RedirectUri != redirect_uri)
                return BadRequest("Invalid redirect URI");

            if (response_type != "code")
                return BadRequest("Unsupported response type");

            // Get the authenticated user's ID from the claims
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User is not authenticated.");

            // Generate authorization code
            var code = GenerateAuthorizationCode();
            var authCode = new AuthorizationCode
            {
                Code = code,
                ClientId = client_id,
                UserId = userId,
                RedirectUri = redirect_uri,
                Scope = scope ?? "",
                Nonce = nonce,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10)
            };

            _context.AuthorizationCodes.Add(authCode);
            await _context.SaveChangesAsync();

            // Redirect back to client with authorization code
            var redirectUrl = $"{redirect_uri}?code={code}";
            if (!string.IsNullOrEmpty(state))
                redirectUrl += $"&state={state}";

            return Redirect(redirectUrl);
        }

        [HttpGet("debug/clients")]
        public async Task<IActionResult> ListClients()
        {
            var clients = await _context.Clients.ToListAsync();
            return Ok(clients);
        }

        [HttpPost("token")]
        public async Task<IActionResult> Token([FromForm] TokenRequest request)
        {
            if (request.grant_type == "authorization_code")
            {
                return await HandleAuthorizationCodeGrant(request);
            }
            else if (request.grant_type == "refresh_token")
            {
                return await HandleRefreshTokenGrant(request);
            }
            else if (request.grant_type == "password")
            {
                return await HandlePasswordGrant(request);
            }

            return BadRequest("Unsupported grant type");
        }
        

        private async Task<IActionResult> HandleAuthorizationCodeGrant(TokenRequest request)
        {
            Console.WriteLine($"[DEBUG] Token request received. ClientId: {request.client_id}, Code: {request.code}");
            
            // Validate client
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == request.client_id && c.IsActive);

            if (client == null)
            {
                Console.WriteLine($"[DEBUG] Client not found or inactive. ClientId: {request.client_id}");
                return Unauthorized("Invalid client credentials");
            }
            
            if (client.ClientSecret != request.client_secret)
            {
                Console.WriteLine($"[DEBUG] Invalid client secret for client: {request.client_id}");
                return Unauthorized("Invalid client credentials");
            }

            // Log all codes in database for debugging
            var allCodes = await _context.AuthorizationCodes.ToListAsync();
            Console.WriteLine($"[DEBUG] All authorization codes in DB: {System.Text.Json.JsonSerializer.Serialize(allCodes)}");

            // Validate authorization code
            var authCode = await _context.AuthorizationCodes
                .FirstOrDefaultAsync(ac => ac.Code == request.code && 
                                        ac.ClientId == request.client_id);

            Console.WriteLine($"[DEBUG] Found auth code: {authCode != null}");
            
            if (authCode == null)
            {
                Console.WriteLine($"[DEBUG] Authorization code not found. Code: {request.code}, ClientId: {request.client_id}");
                return BadRequest("Invalid or expired authorization code");
            }

            if (authCode.IsUsed)
            {
                Console.WriteLine($"[DEBUG] Authorization code already used. Code: {request.code}");
                return BadRequest("Authorization code has already been used");
            }

            if (authCode.ExpiresAt <= DateTime.UtcNow)
            {
                Console.WriteLine($"[DEBUG] Authorization code expired. Code: {request.code}, Expired at: {authCode.ExpiresAt}");
                return BadRequest("Authorization code has expired");
            }

            if (authCode.RedirectUri != request.redirect_uri)
                return BadRequest("Invalid redirect URI");

            // Get user information for token generation first
            var user = await _userManager.FindByIdAsync(authCode.UserId);
            if (user == null)
                return BadRequest("User not found");
                
            // Mark code as used
            authCode.IsUsed = true;
            await _context.SaveChangesAsync();
            
            // Log that we're proceeding with token generation
            Console.WriteLine($"[DEBUG] Proceeding with token generation for user: {user.Id}");

            // Generate tokens with user details
            var accessToken = _tokenService.GenerateAccessToken(
                authCode.UserId,
                user.UserName ?? "",
                user.Email ?? "",
                authCode.ClientId,
                authCode.Scope);
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Store refresh token
            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = authCode.UserId,
                ClientId = authCode.ClientId,
                ExpiresAt = DateTime.UtcNow.AddDays(30)
            };

            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            var scopes = (authCode.Scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string? idToken = null;
            if (scopes.Contains("openid"))
            {
                idToken = _tokenService.GenerateIdToken(
                    authCode.UserId,
                    user.UserName ?? "",
                    user.Email ?? "",
                    authCode.ClientId,
                    authCode.Nonce);
            }

            return Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = refreshToken,
                id_token = idToken,
                scope = authCode.Scope
            });
        }

        private async Task<IActionResult> HandleRefreshTokenGrant(TokenRequest request)
        {
            var storedRefreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == request.refresh_token && 
                                          !rt.IsRevoked && 
                                          rt.ExpiresAt > DateTime.UtcNow);

            if (storedRefreshToken == null)
                return BadRequest("Invalid refresh token");

            // Validate client
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == request.client_id && c.IsActive);

            if (client == null || client.ClientSecret != request.client_secret)
                return Unauthorized("Invalid client credentials");

            if (storedRefreshToken.ClientId != request.client_id)
                return BadRequest("Invalid client for refresh token");

            // Get user information for token generation
            var user = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
            if (user == null)
                return BadRequest("User not found");

            // Generate new access token with user details
            var accessToken = _tokenService.GenerateAccessToken(
                storedRefreshToken.UserId,
                user.UserName ?? "",
                user.Email ?? "",
                storedRefreshToken.ClientId, 
                "read write");

            return Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600
            });
        }

        private async Task<IActionResult> HandlePasswordGrant(TokenRequest request)
        {
            // Validate client
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == request.client_id && c.IsActive);

            if (client == null || client.ClientSecret != request.client_secret)
            {
                return Unauthorized("Invalid client credentials");
            }

            // Find user by username or email
            var user = await _userManager.FindByNameAsync(request.username) ??
                      await _userManager.FindByEmailAsync(request.username);

            if (user == null)
            {
                return Unauthorized("Invalid username or password");
            }

            // Verify password
            var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.password);
            if (!isPasswordValid)
            {
                return Unauthorized("Invalid username or password");
            }

            // Generate tokens
            var accessToken = _tokenService.GenerateAccessToken(
                user.Id,
                user.UserName ?? "",
                user.Email ?? "",
                client.ClientId,
                request.scope ?? "read write");

            var refreshToken = _tokenService.GenerateRefreshToken();

            // Store refresh token
            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                ClientId = client.ClientId,
                ExpiresAt = DateTime.UtcNow.AddDays(30)
            };

            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = refreshToken,
                scope = request.scope ?? "read write"
            });
        }

        private static string GenerateAuthorizationCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
        }
    }

    public class TokenRequest
    {
        public string grant_type { get; set; } = string.Empty;
        public string client_id { get; set; } = string.Empty;
        public string client_secret { get; set; } = string.Empty;
        public string code { get; set; } = string.Empty;
        public string redirect_uri { get; set; } = string.Empty;
        public string refresh_token { get; set; } = string.Empty;
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
        public string scope { get; set; } = string.Empty;
    }
}