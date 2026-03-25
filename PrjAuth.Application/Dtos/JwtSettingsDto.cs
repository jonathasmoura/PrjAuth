using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Dtos
{
	public class JwtSettingsDto
	{
		public string SecretKey { get; set; } = string.Empty;
		public string Issuer { get; set; } = string.Empty;
		public string Audience { get; set; } = string.Empty;
		public int AccessTokenExpirationMinutes { get; set; } = 15;
		public int RefreshTokenExpirationDays { get; set; } = 7;
	}
}
