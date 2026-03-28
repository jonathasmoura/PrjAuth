using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface ITokenBlacklistHelper
	{
		/// <summary>
		/// Tenta colocar o token de acesso atual na blacklist, se disponível no header Authorization ou nas claims do usuário.
		/// Implementação deve tratar erros internamente e não lançar.
		/// </summary>
		Task TryBlacklistCurrentAccessTokenAsync();
	}
}
