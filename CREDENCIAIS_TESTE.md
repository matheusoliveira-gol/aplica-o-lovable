# 🔐 Credenciais de Teste - GolFind

## Primeiro Acesso

No primeiro acesso, você será redirecionado automaticamente para criar o primeiro usuário administrador.

**Dados sugeridos para teste:**
- Email: admin@golfind.com
- Senha: admin123456
- Nome: Administrador

## Como Iniciar

1. **Servidor Backend:**
   ```bash
   cd server
   npm install
   npm start
   ```
   Servidor rodará em: http://localhost:3001

2. **Frontend:**
   ```bash
   npm run dev
   ```
   Aplicação rodará em: http://localhost:5173

3. **Acessar Sistema:**
   - Acesse http://localhost:5173
   - Será redirecionado para /setup
   - Crie o primeiro admin
   - Faça login

## Segurança Implementada ✅

- ✅ Autenticação JWT (tokens de 24h)
- ✅ Autorização baseada em roles
- ✅ Proteção contra SQL injection
- ✅ Criptografia AES-256-GCM para dados sensíveis
- ✅ Senhas com hash bcrypt
- ✅ Sem credenciais hardcoded
- ✅ Validação de permissões server-side

## Roles Disponíveis

- **admin**: Acesso total
- **gestor**: Criar, ler e atualizar
- **operador**: Ler e atualizar
- **visualizador**: Apenas leitura
