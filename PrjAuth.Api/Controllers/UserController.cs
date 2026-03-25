using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using System.Security.Claims;

namespace PrjAuth.Api.Controllers
{
	[ApiController]
	[Route("v1/[controller]")]
	public class UsersController : ControllerBase
	{
		private readonly IUserService _userService;

		public UsersController(IUserService userService)
		{
			_userService = userService;
		}

		[HttpGet("profile")]
		public async Task<IActionResult> GetProfile()
		{
			var idClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			if (string.IsNullOrWhiteSpace(idClaim) || !Guid.TryParse(idClaim, out var userId))
				return Unauthorized();

			var user = await _userService.FindUserById(userId);
			if (user == null)
				return NotFound();

			return Ok(new UserDto
			{
				Id = user.Id,
				Username = user.Username,
				Email = user.Email,
				Roles = user.Roles
			});
		}

		[HttpGet]
		[Authorize(Roles = "Admin")]
		public async Task<IActionResult> GetAllUsers()
		{
			var users = await _userService.GetAllUsersAsync();

			return Ok(users);
		}
	}
}


