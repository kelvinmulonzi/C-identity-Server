using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthorizationServer.Models;
using System.ComponentModel.DataAnnotations;

namespace AuthorizationServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public AccountController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        public class RegisterDto
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            public string Username { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            // The password must meet your Identity configuration requirements
            public string Password { get; set; } = string.Empty;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser 
            { 
                UserName = model.Username, 
                Email = model.Email,
                // Optional: set to true to skip email confirmation for a simplified demo
                EmailConfirmed = true 
            };

            // Use UserManager to hash the password and persist the user
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Return a success message and the user's details
                return Created(string.Empty, new 
                { 
                    Message = "User registered successfully. You can now log in.", 
                    UserId = user.Id,
                    Username = user.UserName
                });
            }

            // Return Identity errors if registration failed
            return BadRequest(result.Errors);
        }
    }
}