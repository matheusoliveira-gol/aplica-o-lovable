# GolFind - Guia de Instalação em Servidor Linux

Sistema GolFind com backend Node.js + SQLite para rede local offline.

## 📋 Visão Geral

- **Frontend**: React + Vite (porta 8080)
- **Backend**: Node.js + Express + SQLite (porta 3001)
- **Banco de Dados**: SQLite (arquivo local centralizado)
- **Rede**: Todos os usuários da rede local acessam o mesmo banco de dados

## 🚀 Instalação Rápida

### 1. Preparar o Servidor

```bash
# Instalar Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git

# Verificar instalação
node --version
npm --version
```

### 2. Clonar o Projeto

```bash
# Criar diretório e copiar arquivos
sudo mkdir -p /opt/golfind
sudo chown $USER:$USER /opt/golfind
cd /opt/golfind

# Copiar seu projeto para /opt/golfind
# (via git clone, scp, ou pendrive)
```

### 3. Configurar o Backend

```bash
cd /opt/golfind/server
npm install
```

### 4. Configurar o Frontend

```bash
cd /opt/golfind

# Descobrir o IP do servidor
IP_SERVIDOR=$(hostname -I | awk '{print $1}')
echo "IP do Servidor: $IP_SERVIDOR"

# Editar o arquivo .env.local
nano .env.local
# Alterar para: VITE_API_URL=http://[SEU_IP]:3001
# Exemplo: VITE_API_URL=http://192.168.1.100:3001

# Instalar dependências e fazer build
npm install
npm run build
```

### 5. Iniciar os Serviços

#### Opção A: Teste Manual (temporário)

```bash
# Terminal 1 - Backend
cd /opt/golfind/server
npm start

# Terminal 2 - Frontend
cd /opt/golfind
npx serve -s dist -l 8080
```

#### Opção B: Como Serviço (permanente)

**Backend Service:**
```bash
sudo nano /etc/systemd/system/golfind-backend.service
```

Colar:
```ini
[Unit]
Description=GolFind Backend
After=network.target

[Service]
Type=simple
User=seu_usuario_aqui
WorkingDirectory=/opt/golfind/server
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Frontend Service:**
```bash
sudo nano /etc/systemd/system/golfind-frontend.service
```

Colar:
```ini
[Unit]
Description=GolFind Frontend
After=network.target

[Service]
Type=simple
User=seu_usuario_aqui
WorkingDirectory=/opt/golfind
ExecStart=/usr/bin/npx serve -s dist -l 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Ativar:**
```bash
# Substituir "seu_usuario_aqui" pelos serviços criados acima
sudo systemctl daemon-reload
sudo systemctl enable golfind-backend golfind-frontend
sudo systemctl start golfind-backend golfind-frontend

# Verificar status
sudo systemctl status golfind-backend
sudo systemctl status golfind-frontend
```

### 6. Configurar Firewall

```bash
# Ubuntu/Debian
sudo ufw allow 8080/tcp
sudo ufw allow 3001/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=3001/tcp
sudo firewall-cmd --reload
```

## 🌐 Acessar o Sistema

No navegador dos computadores da rede:
```
http://[IP_DO_SERVIDOR]:8080
```

Exemplo: `http://192.168.1.100:8080`

**Credenciais padrão:**
- Email: `admin@golfind.com`
- Senha: `admin123`

## 📁 Estrutura do Projeto

```
/opt/golfind/
├── server/
│   ├── index.js          # Backend API
│   ├── package.json      # Dependências do backend
│   ├── golfind.db        # Banco de dados SQLite (criado automaticamente)
│   └── README.md         # Documentação do backend
├── src/                  # Código fonte React
├── dist/                 # Build do frontend (após npm run build)
├── .env.local            # Configuração da URL da API
├── package.json          # Dependências do frontend
└── README-DEPLOY.md      # Este arquivo
```

## 🔧 Comandos Úteis

```bash
# Ver logs do backend
sudo journalctl -u golfind-backend -f

# Ver logs do frontend
sudo journalctl -u golfind-frontend -f

# Reiniciar serviços
sudo systemctl restart golfind-backend
sudo systemctl restart golfind-frontend

# Parar serviços
sudo systemctl stop golfind-backend golfind-frontend

# Backup do banco de dados
cp /opt/golfind/server/golfind.db ~/golfind-backup-$(date +%Y%m%d).db
```

## 🔄 Atualizar o Sistema

Após modificar o código:

```bash
cd /opt/golfind

# Rebuild do frontend
npm run build

# Reiniciar serviços
sudo systemctl restart golfind-backend
sudo systemctl restart golfind-frontend
```

## 🛠️ Solução de Problemas

### Não consigo acessar pela rede

1. **Verificar se os serviços estão rodando:**
   ```bash
   sudo systemctl status golfind-backend
   sudo systemctl status golfind-frontend
   ```

2. **Verificar portas:**
   ```bash
   sudo netstat -tlnp | grep -E '8080|3001'
   ```

3. **Testar do próprio servidor:**
   ```bash
   curl http://localhost:3001/api/artigos
   curl http://localhost:8080
   ```

4. **Verificar firewall:**
   ```bash
   sudo ufw status  # Ubuntu
   sudo firewall-cmd --list-all  # CentOS
   ```

### Erro de permissão no banco de dados

```bash
sudo chown seu_usuario:seu_usuario /opt/golfind/server/golfind.db
chmod 644 /opt/golfind/server/golfind.db
```

### Backend não inicia

```bash
# Ver erro detalhado
sudo journalctl -u golfind-backend -n 50

# Testar manualmente
cd /opt/golfind/server
node index.js
```

## 💾 Backup Automático

Criar script de backup:

```bash
sudo nano /usr/local/bin/backup-golfind.sh
```

Conteúdo:
```bash
#!/bin/bash
BACKUP_DIR="/backup/golfind"
mkdir -p $BACKUP_DIR
cp /opt/golfind/server/golfind.db "$BACKUP_DIR/golfind-$(date +%Y%m%d-%H%M%S).db"
# Manter apenas 30 últimos backups
find $BACKUP_DIR -name "golfind-*.db" -type f -mtime +30 -delete
echo "Backup criado: $(date)"
```

Tornar executável e agendar:
```bash
sudo chmod +x /usr/local/bin/backup-golfind.sh
sudo crontab -e
```

Adicionar (backup diário às 2h):
```
0 2 * * * /usr/local/bin/backup-golfind.sh >> /var/log/golfind-backup.log 2>&1
```

## 📞 Suporte

Para problemas, verifique:
1. Logs do sistema: `sudo journalctl -xe`
2. Logs do backend: `sudo journalctl -u golfind-backend -f`
3. Logs do frontend: `sudo journalctl -u golfind-frontend -f`
4. Arquivo do banco: `/opt/golfind/server/golfind.db` deve existir
5. Conexão de rede: `ping [IP_DO_SERVIDOR]` de outro computador

## 🔐 Segurança

⚠️ **Importante para produção:**

1. **Altere a senha padrão** após primeiro acesso
2. **Configure backup regular** do banco de dados
3. **Restrinja acesso ao firewall** apenas à sua rede local
4. **Não exponha** as portas para a internet pública
5. **Use HTTPS** se necessário acesso externo (nginx + certbot)

## 📊 Informações do Banco

- **Localização**: `/opt/golfind/server/golfind.db`
- **Tipo**: SQLite 3
- **Tamanho inicial**: ~100 KB
- **Crescimento**: Varia conforme uso
- **Compactação**: SQLite compacta automaticamente

Para ver dados do banco:
```bash
sqlite3 /opt/golfind/server/golfind.db
# Comandos úteis no sqlite:
# .tables              - listar tabelas
# .schema tabela      - ver estrutura
# SELECT * FROM pessoas;  - ver dados
# .quit               - sair
```
