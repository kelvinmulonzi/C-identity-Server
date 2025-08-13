using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ResourceServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UserController : ControllerBase
    {
        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var clientId = User.FindFirst("client_id")?.Value;
            var scope = User.FindFirst("scope")?.Value;

            return Ok(new
            {
                userId = userId,
                clientId = clientId,
                scope = scope,
                message = "This is protected user data",
                timestamp = DateTime.UtcNow
            });
        }

        [HttpGet("data")]
        public IActionResult GetData()
        {
            var scope = User.FindFirst("scope")?.Value;
            
            if (!scope?.Contains("read") == true)
            {
                return Forbid("Insufficient scope");
            }

            return Ok(new
            {
                data = new[] { "Item 1", "Item 2", "Item 3" },
                message = "This endpoint requires 'read' scope"
            });
        }

        [HttpPost("data")]
        public IActionResult CreateData([FromBody] string data)
        {
            var scope = User.FindFirst("scope")?.Value;
            
            if (!scope?.Contains("write") == true)
            {
                return Forbid("Insufficient scope");
            }

            return Ok(new
            {
                message = $"Data '{data}' created successfully",
                requiredScope = "write"
            });
        }
    }
}