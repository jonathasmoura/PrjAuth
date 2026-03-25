## 🔐 Auth API (.NET 8) — Arquitetura Segura, Escalável e Pronta para Produção

Projeto de autenticação e autorização desenvolvido em C# / .NET 8, com foco em segurança avançada, escalabilidade e boas práticas de arquitetura moderna.

A aplicação implementa um fluxo completo de autenticação baseado em JWT + Refresh Tokens, incluindo mecanismos de revogação ativa, proteção contra vulnerabilidades comuns e suporte a ambientes distribuídos (cloud-ready / load-balanced).

💡 Demonstra experiência prática com design de APIs seguras, arquitetura em camadas, controle de acesso e engenharia de software para sistemas críticos.

## 🚀 Destaques Técnicos

- 🔐 Implementação completa de Authentication & Authorization (AuthN/AuthZ)
- 🧠 Uso estratégico de JWT com controle de ciclo de vida (`exp`, `jti`, rotação)
- 🔄 Refresh Tokens rotacionáveis com persistência segura
- 🚫 Revogação de tokens em tempo real via blacklist (JTI)
- 🍪 Armazenamento seguro de refresh tokens em cookies `HttpOnly` + `Secure` + `SameSite=Strict`
- ⚖️ Preparado para ambientes load-balanced / distribuídos:
  - Suporte a múltiplas chaves (`primary` / `secondary`)
  - Suporte opcional a `Redis` via `IDistributedCache` (`Jwt:UseRedis` / `Redis` section)
- 🛡️ Hardening de segurança:
  - Validação de algoritmo no header do token (protege contra downgrade attacks)
  - Validação de `issuer` / `audience`
  - `ValidateIssuerSigningKey = true` e `ClockSkew` restrito (1 min)
  - `RequireHttpsMetadata = true` no `JwtBearer`
- 🧩 Helpers para inspeção de tokens — agora **sempre validam assinatura** antes de expor claims (podem optar por ignorar lifetime quando usados para refresh)
- 🔐 Suporte assimétrico: geração/validação com RSA usando `Jwt:PrivateKey` / `Jwt:PublicKey` e `KeyId`
- 🧪 Testes automatizados (unitários + integração) cobrindo fluxos críticos e segurança
- 📦 Código preparado para evolução (extensível para OAuth, Identity Providers, etc.)

## 📡 Endpoints da API (rotas reais)

Observação: os controllers atuais expõem rotas diferentes — verifique os controllers ao usar a API.

- AuthController: definido com `[Route("api/[controller]")]` → endpoints reais:
  - POST `/api/auth/login` — autentica usuário e retorna `accessToken` + `refreshToken` (cookie)
  - POST `/api/auth/refresh` — renova tokens via cookie seguro
  - POST `/api/auth/logout` — revoga tokens e limpa cookie
  - POST `/api/auth/register` — cria novo usuário

- UsersController: definido com `[Route("v1/[controller]")]` → endpoints:
  - GET `/v1/users/profile` — perfil do usuário autenticado
  - GET `/v1/users` — admin (requere role `Admin`)

Se preferir padronizar para `/v1/auth/*`, altere a rota do `AuthController` para `[Route("v1/[controller]")]` ou atualize a documentação conforme desejado.

## 🔎 Fluxos importantes

- Login: retorna `accessToken` no corpo e salva `refreshToken` em cookie `HttpOnly`.
- Refresh: valida refresh token persistido, rotaciona refresh token e emite novo access token.
- Logout: revoga refresh token e faz blacklist do `jti` do access token (usa helpers que validam assinatura).
- Blacklist: implementado com `IDistributedCache` (pode usar Redis em produção).

## ⚙️ Configuração (principais chaves)
- `Jwt:Key` (symmetric) ou `Jwt:PrimaryKey`/`Jwt:SecondaryKey` para load-balancing
- `Jwt:PrivateKey` / `Jwt:PublicKey` / `Jwt:KeyId` — suporte RSA (base64)
- `Jwt:Issuer`, `Jwt:Audience`, `Jwt:AccessTokenExpirationMinutes`
- `Jwt:UseRedis` e seção `Redis` para configuração de cache distribuído
- `RateLimiting` — seção para proteção de endpoints sensíveis

Atenção: não comite segredos em `appsettings.json` para produção — use variáveis de ambiente, Azure Key Vault, AWS Secrets Manager ou similar.

## 🛡️ Observações de Segurança
- Helpers que leem `exp` / `jti` agora validam assinatura do token antes de retornar valores; nunca confie em parse puro (`ReadJwtToken`) para decisões de segurança.
- Mantido controle de algoritmo no header para evitar troca de algoritmo.
- Política de blacklist garante controle de sessão mesmo em arquiteturas stateless.

## 🏗️ Arquitetura
Estrutura inspirada em Clean Architecture:

- `Api` → Controllers, Middlewares
- `Application` → Casos de uso, DTOs, regras de negócio
- `Domain` → Entidades, contratos
- `Infra` → Persistência (EF Core), integrações
- `Tests` → Testes unitários e de integração

## 🧪 Como executar
1. Configurar variáveis/jkeys JWT e demais secrets (localmente via `appsettings.Development.json` ou variáveis de ambiente)
2. Build:
   - `dotnet build`
3. Executar API:
   - `dotnet run --project PrjAuth.Api`
4. Executar testes:
   - `dotnet test`

## ☁️ Pronto para Produção
- Compatível com ambientes distribuídos
- Stateless authentication com controle de sessão via blacklist
- Fácil integração com API Gateways, Identity Providers e microsserviços

## 🤝 Contribuição
Contribuições são bem-vindas. Antes de abrir PR:
- Rode `dotnet test`
- Siga padrões C# 12 / .NET 8
- Mantenha cobertura de testes e respeite a arquitetura proposta
