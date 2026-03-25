using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Dtos
{
	public class RegisterResponseDto
	{
		public bool Flag { get; set; }
		public string Message { get; set; } = null!;
	}
}
