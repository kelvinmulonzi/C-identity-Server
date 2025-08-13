using System.Text;
using System.Text.Json;

namespace ClientApp.Services
{
    public class OAuth2Service
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;

        public OAuth2Service(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
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
            var response = await _httpClient.PostAsync(tokenEndpoint, content);
            
            if (response.IsSuccessStatusCode)
            {
                var jsonString = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<TokenResponse>(jsonString, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                })!;
            }

            throw new Exception("Failed to exchange code for token");
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