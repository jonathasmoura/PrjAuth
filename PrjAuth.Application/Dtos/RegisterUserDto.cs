using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Dtos
{
	public class RegisterUserDto
	{
		public string Name { get; set; } = null!;
		public string? LastName { get; set; }
		public string Email { get; set; } = null!;
		public string Password { get; set; } = null!;
		public string ConfirmPassword { get; set; } = null!;
		public bool IsAdmin { get; set; }
	}
}
