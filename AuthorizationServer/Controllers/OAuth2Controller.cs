using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthorizationServer.Data;
using AuthorizationServer.Models;
using AuthorizationServer.Services;
using System.Security.Cryptography;
using System.Text;

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

        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize(
            [FromQuery] string client_id,
            [FromQuery] string redirect_uri,
            [FromQuery] string response_type,
            [FromQuery] string scope,
            [FromQuery] string state)
        {
            // Validate client
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == client_id && c.IsActive);
            
            if (client == null)
                return BadRequest("Invalid client");

            if (client.RedirectUri != redirect_uri)
                return BadRequest("Invalid redirect URI");

            if (response_type != "code")
                return BadRequest("Unsupported response type");

            // In a real implementation, redirect to login page if user not authenticated
            // For this example, we'll assume user is authenticated
            var userId = "test-user-id"; // This should come from authentication

            // Generate authorization code
            var code = GenerateAuthorizationCode();
            var authCode = new AuthorizationCode
            {
                Code = code,
                ClientId = client_id,
                UserId = userId,
                RedirectUri = redirect_uri,
                Scope = scope ?? "",
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

            return BadRequest("Unsupported grant type");
        }

        private async Task<IActionResult> HandleAuthorizationCodeGrant(TokenRequest request)
        {
            // Validate client
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ClientId == request.client_id && c.IsActive);

            if (client == null || client.ClientSecret != request.client_secret)
                return Unauthorized("Invalid client credentials");

            // Validate authorization code
            var authCode = await _context.AuthorizationCodes
                .FirstOrDefaultAsync(ac => ac.Code == request.code && 
                                          ac.ClientId == request.client_id &&
                                          !ac.IsUsed && 
                                          ac.ExpiresAt > DateTime.UtcNow);

            if (authCode == null)
                return BadRequest("Invalid or expired authorization code");

            if (authCode.RedirectUri != request.redirect_uri)
                return BadRequest("Invalid redirect URI");

            // Mark code as used
            authCode.IsUsed = true;
            await _context.SaveChangesAsync();

            // Generate tokens
            var accessToken = _tokenService.GenerateAccessToken(authCode.UserId, authCode.ClientId, authCode.Scope);
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

            return Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = refreshToken,
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

            // Generate new access token
            var accessToken = _tokenService.GenerateAccessToken(
                storedRefreshToken.UserId, 
                storedRefreshToken.ClientId, 
                "read write");

            return Ok(new
            {
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600
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
    }
}