using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Configuration
{
	public sealed class TokenSecrets
	{
		public string Primary { get; }
		public string Secondary { get; }

		public TokenSecrets(string primary, string secondary)
		{
			Primary = primary ?? string.Empty;
			Secondary = secondary ?? string.Empty;
		}
	}
}
