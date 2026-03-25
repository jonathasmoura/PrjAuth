using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface ITokenBlackListService
	{
		Task<bool> IsTokenBlacklistedAsync(string jti);
		Task BlacklistTokenAsync(string jti, DateTime expiration);
	}
}
