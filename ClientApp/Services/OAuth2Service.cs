using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace ClientApp.Services
{
    public class OAuth2Service
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<OAuth2Service> _logger;

        public OAuth2Service(HttpClient httpClient, IConfiguration configuration, ILogger<OAuth2Service> logger)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<TokenResponse> ExchangeCodeForToken(string code, string redirectUri)
        {
            var tokenEndpoint = _configuration["OAuth2:TokenEndpoint"]!;
            var clientId = _configuration["OAuth2:ClientId"]!;
            var clientSecret = _configuration["OAuth2:ClientSecret"]!;

            var parameters = new Dictionary<string, string>
            {
                {"grant_type", "authorization_code"},
                {"client_id", clientId},
                {"client_secret", clientSecret},
                {"code", code},
                {"redirect_uri", redirectUri}
            };

            var content = new FormUrlEncodedContent(parameters);
            _logger.LogInformation("Sending token request to {TokenEndpoint}", tokenEndpoint);
            _logger.LogDebug("Request parameters: {Parameters}", string.Join(", ", parameters.Select(p => $"{p.Key}={p.Value}")));
            
            var response = await _httpClient.PostAsync(tokenEndpoint, content);
            var responseContent = await response.Content.ReadAsStringAsync();
            
            _logger.LogInformation("Token response: {StatusCode} - {Response}", response.StatusCode, responseContent);
            
            if (response.IsSuccessStatusCode)
            {
                try
                {
                    var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    })!;
                    
                    _logger.LogInformation("Successfully obtained access token");
                    return tokenResponse;
                }
                catch (JsonException ex)
                {
                    _logger.LogError(ex, "Failed to deserialize token response: {Response}", responseContent);
                    throw new Exception("Invalid token response format");
                }
            }
            
            _logger.LogError("Token request failed with status code {StatusCode}. Response: {Response}", 
                response.StatusCode, responseContent);
                
            throw new Exception($"Failed to exchange code for token. Status: {response.StatusCode}, Response: {responseContent}");
        }

        public async Task<string> CallProtectedResource(string accessToken, string resourceUrl)
        {
            _httpClient.DefaultRequestHeaders.Authorization = 
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.GetAsync(resourceUrl);
            return await response.Content.ReadAsStringAsync();
        }
    }

    public class TokenResponse
    {
        public string access_token { get; set; } = string.Empty;
        public string token_type { get; set; } = string.Empty;
        public int expires_in { get; set; }
        public string refresh_token { get; set; } = string.Empty;
        public string scope { get; set; } = string.Empty;
    }
}