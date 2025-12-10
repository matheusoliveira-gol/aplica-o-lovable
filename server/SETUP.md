# Configuração do Servidor Seguro GolFind

## 1. Gerar Chaves de Segurança

Antes de iniciar o servidor, você DEVE gerar chaves de segurança únicas:

```bash
cd server

# Gerar chave de criptografia (32 caracteres)
node -e "console.log('ENCRYPTION_KEY=' + require('crypto').randomBytes(16).toString('hex'))"

# Gerar chave JWT (64 caracteres)
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
```

## 2. Configurar arquivo .env

Edite o arquivo `server/.env` e substitua os valores padrão pelas chaves geradas:

```env
ENCRYPTION_KEY=SUA_CHAVE_DE_32_CARACTERES_AQUI
JWT_SECRET=SUA_CHAVE_JWT_DE_64_CARACTERES_AQUI
PORT=3001
```

**IMPORTANTE:** Faça backup dessas chaves! Se perder a ENCRYPTION_KEY, não será possível descriptografar os dados!

## 3. Instalar Dependências

```bash
npm install
```

## 4. Iniciar o Servidor

```bash
npm start
```

## 5. Primeiro Acesso

1. Acesse http://localhost:5173 no navegador
2. Você será redirecionado para a página de configuração inicial
3. Crie o primeiro usuário administrador
4. Faça login com as credenciais criadas

## Segurança Implementada

✓ Autenticação JWT com tokens de 24h
✓ Autorização baseada em roles (admin, gestor, operador, visualizador)
✓ Proteção contra SQL injection com whitelists de colunas
✓ Criptografia AES-256-GCM para dados sensíveis
✓ Senhas com hash bcrypt
✓ Mensagens de erro genéricas (sem vazamento de informações)
