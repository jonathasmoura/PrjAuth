using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;

namespace PrjAuth.Api.Controllers
{
	[Route("v1/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{

		private readonly IAuthService _authService;
		private readonly IUserService _userService;
		private readonly ITokenService _tokenService;
		private readonly ITokenBlackListService _tokenBlackListService;
		private readonly ILogger<AuthController> _logger;

		public AuthController(IAuthService authService, IUserService userService, ILogger<AuthController> logger, ITokenService tokenService, ITokenBlackListService tokenBlackListService)
		{
			_authService = authService;
			_userService = userService;
			_logger = logger;
			_tokenService = tokenService;
			_tokenBlackListService = tokenBlackListService;
		}

		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] LoginUserDto request)
		{
			if (!ModelState.IsValid)
				return BadRequest(ModelState);

			var response = await _authService.AuthenticateAsync(request);

			if (response == null)
				return Unauthorized(new { message = "Usuário ou senha inválidos" });
			var cookieOptions = new CookieOptions
			{
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Strict,
				Expires = DateTime.UtcNow.AddDays(7)
			};

			Response.Cookies.Append("refreshToken", response.RefreshToken, cookieOptions);

			return Ok(new
			{
				accessToken = response.AccessToken,
				expiresAt = response.ExpiresAt,
				user = response.User
			});
		}

		[HttpPost("refresh")]
		public async Task<IActionResult> RefreshToken()
		{
			var refreshToken = Request.Cookies["refreshToken"];

			if (string.IsNullOrEmpty(refreshToken))
				return Unauthorized(new { message = "Refresh token não encontrado" });

			var response = await _authService.RefreshTokenAsync(refreshToken);

			if (response == null)
				return Unauthorized(new { message = "Refresh token inválido" });

			var cookieOptions = new CookieOptions
			{
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Strict,
				Expires = DateTime.UtcNow.AddDays(7)
			};

			Response.Cookies.Append("refreshToken", response.RefreshToken, cookieOptions);

			return Ok(new
			{
				accessToken = response.AccessToken,
				expiresAt = response.ExpiresAt,
				user = response.User
			});
		}

		[HttpPost("logout")]
		[Authorize]
		public async Task<IActionResult> Logout([FromBody] LogoutDto? request)
		{
			var refreshToken = Request.Cookies["refreshToken"];

			string? accessToken = null;
			var authHeader = Request.Headers["Authorization"].FirstOrDefault();
			if (!string.IsNullOrWhiteSpace(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
			{
				accessToken = authHeader.Substring("Bearer ".Length).Trim();
			}
			else if (!string.IsNullOrWhiteSpace(request?.AccessToken))
			{
				accessToken = request!.AccessToken;
			}

			if (!string.IsNullOrEmpty(refreshToken))
			{
				await _authService.RevokeTokenAsync(refreshToken);
			}

			if (!string.IsNullOrWhiteSpace(accessToken))
			{
				try
				{
					var jti = _tokenService.GetJti(accessToken);
					if (!string.IsNullOrEmpty(jti))
					{
						var expiration = _tokenService.GetTokenExpirationUtc(accessToken) ?? DateTime.UtcNow.AddMinutes(1);
						await _tokenBlackListService.BlacklistTokenAsync(jti, expiration);
					}
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, "Falha ao extrair jti do access token informado no logout.");
				}
			}

			Response.Cookies.Delete("refreshToken");

			_logger.LogInformation("Usuário {User} deslogado", User.Identity?.Name);

			return Ok(new { message = "Logout realizado com sucesso" });
		}

		[HttpPost("register")]
		public async Task<ActionResult<RegisterResponseDto>> RegisterUser([FromBody] RegisterUserDto registerUserDto)
		{
			if (!ModelState.IsValid)
				return BadRequest(ModelState);

			try
			{
				var registerResponse = await _userService.RegisterUserAsync(registerUserDto);
				if (registerResponse == null)
					return StatusCode(StatusCodes.Status500InternalServerError, "Erro ao registrar usuário.");

				if (!registerResponse.Flag)
					return BadRequest(registerResponse);

				return Ok(registerResponse);
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Erro durante registro de usuário");
				return StatusCode(StatusCodes.Status500InternalServerError, ex.Message);
			}
		}
	}
}
