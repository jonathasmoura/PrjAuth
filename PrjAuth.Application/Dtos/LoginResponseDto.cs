using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Dtos
{
	public class LoginResponseDto
	{
		public bool Flag { get; set; }
		public string Message { get; set; } = null!;
		public string Token { get; set; } = string.Empty;

	}
}
