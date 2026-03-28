using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface IClientIpExtractor
	{
		/// <summary>
		/// Retorna o IP do cliente com prioridade para cabeçalho X-Forwarded-For, caso exista.
		/// Retorna string.Empty se não for possível extrair.
		/// </summary>
		string GetClientIp();
	}
}
