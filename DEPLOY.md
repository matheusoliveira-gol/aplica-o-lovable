# Deploy do GolFind em Servidor Linux

## Visão Geral
O GolFind agora funciona com um backend centralizado em Node.js + SQLite, permitindo que todos os usuários da rede local compartilhem os mesmos dados.

## Arquitetura
- **Frontend**: React (Vite) - Porta 8080
- **Backend**: Node.js + Express + SQLite - Porta 3001
- **Banco de Dados**: SQLite (arquivo local no servidor)

## Instalação Passo a Passo

### 1. Preparar o Servidor Linux

```bash
# Atualizar o sistema
sudo apt update && sudo apt upgrade -y

# Instalar Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verificar instalação
node --version
npm --version
```

### 2. Clonar/Copiar o Projeto para o Servidor

```bash
# Opção 1: Via Git
git clone [seu-repositorio] /opt/golfind
cd /opt/golfind

# Opção 2: Via SCP (do seu computador local)
scp -r ./golfind usuario@servidor:/opt/
```

### 3. Instalar Dependências

```bash
cd /opt/golfind

# Backend
cd server
npm install
cd ..

# Frontend
npm install
```

### 4. Configurar a API

Editar o arquivo `.env.local` com o IP do servidor:

```bash
nano .env.local
```

Alterar para:
```
VITE_API_URL=http://[IP_DO_SERVIDOR]:3001
```

Exemplo: `VITE_API_URL=http://192.168.1.100:3001`

### 5. Fazer Build do Frontend

```bash
npm run build
```

### 6. Iniciar os Serviços

#### Opção A: Manualmente (para testes)

Terminal 1 - Backend:
```bash
cd /opt/golfind/server
npm start
```

Terminal 2 - Frontend:
```bash
cd /opt/golfind
npm install -g serve
serve -s dist -l 8080
```

#### Opção B: Como Serviço Systemd (Recomendado)

**Criar serviço do Backend:**

```bash
sudo nano /etc/systemd/system/golfind-backend.service
```

Conteúdo:
```ini
[Unit]
Description=GolFind Backend API
After=network.target

[Service]
Type=simple
User=seu_usuario
WorkingDirectory=/opt/golfind/server
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Criar serviço do Frontend:**

```bash
sudo nano /etc/systemd/system/golfind-frontend.service
```

Conteúdo:
```ini
[Unit]
Description=GolFind Frontend
After=network.target

[Service]
Type=simple
User=seu_usuario
WorkingDirectory=/opt/golfind
ExecStart=/usr/bin/npx serve -s dist -l 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Ativar e iniciar os serviços:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable golfind-backend
sudo systemctl enable golfind-frontend
sudo systemctl start golfind-backend
sudo systemctl start golfind-frontend

# Verificar status
sudo systemctl status golfind-backend
sudo systemctl status golfind-frontend
```

### 7. Configurar Firewall

```bash
# Ubuntu/Debian (UFW)
sudo ufw allow 8080/tcp
sudo ufw allow 3001/tcp
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=3001/tcp
sudo firewall-cmd --reload
```

### 8. Descobrir o IP do Servidor

```bash
ip addr show | grep inet
# ou
hostname -I
```

### 9. Acessar pela Rede Local

No navegador dos computadores da rede:
```
http://[IP_DO_SERVIDOR]:8080
```

Exemplo: `http://192.168.1.100:8080`

## Configuração Avançada com Nginx (Opcional)

Para usar a porta 80 padrão e melhor performance:

### 1. Instalar Nginx

```bash
sudo apt install nginx -y
```

### 2. Configurar o Site

```bash
sudo nano /etc/nginx/sites-available/golfind
```

Conteúdo:
```nginx
server {
    listen 80;
    server_name [IP_DO_SERVIDOR];

    # Frontend
    location / {
        root /opt/golfind/dist;
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, must-revalidate";
    }

    # API Backend
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### 3. Ativar o Site

```bash
sudo ln -s /etc/nginx/sites-available/golfind /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 4. Atualizar .env.local

```bash
nano /opt/golfind/.env.local
```

Alterar para:
```
VITE_API_URL=http://[IP_DO_SERVIDOR]
```

### 5. Rebuild e Restart

```bash
cd /opt/golfind
npm run build
sudo systemctl restart golfind-frontend
```

Agora acesse via: `http://[IP_DO_SERVIDOR]` (sem porta)

## Backup Automático

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
# Manter apenas os últimos 30 backups
ls -t $BACKUP_DIR/golfind-*.db | tail -n +31 | xargs rm -f
```

Tornar executável:
```bash
sudo chmod +x /usr/local/bin/backup-golfind.sh
```

Agendar no crontab:
```bash
sudo crontab -e
```

Adicionar (backup diário às 2h):
```
0 2 * * * /usr/local/bin/backup-golfind.sh
```

## Comandos Úteis

```bash
# Ver logs do backend
sudo journalctl -u golfind-backend -f

# Ver logs do frontend
sudo journalctl -u golfind-frontend -f

# Reiniciar serviços
sudo systemctl restart golfind-backend
sudo systemctl restart golfind-frontend

# Parar serviços
sudo systemctl stop golfind-backend
sudo systemctl stop golfind-frontend

# Verificar portas em uso
sudo netstat -tlnp | grep -E '8080|3001'

# Backup manual
cp /opt/golfind/server/golfind.db /backup/golfind.db.backup
```

## Atualização do Sistema

Para atualizar após mudanças no código:

```bash
cd /opt/golfind
git pull  # se usando Git
npm run build
sudo systemctl restart golfind-backend
sudo systemctl restart golfind-frontend
```

## Solução de Problemas

### Porta já em uso
```bash
# Verificar o que está usando a porta
sudo lsof -i :8080
sudo lsof -i :3001

# Matar processo se necessário
sudo kill -9 [PID]
```

### Permissões do banco de dados
```bash
sudo chown seu_usuario:seu_usuario /opt/golfind/server/golfind.db
sudo chmod 644 /opt/golfind/server/golfind.db
```

### Não consegue acessar da rede
- Verificar firewall
- Verificar se o servidor está ouvindo em 0.0.0.0 (não só localhost)
- Testar conectividade: `ping [IP_DO_SERVIDOR]`

## Credenciais Padrão

- **Email**: admin@golfind.com
- **Senha**: admin123

**IMPORTANTE**: Altere essas credenciais em produção!

## Localização dos Arquivos

- **Banco de Dados**: `/opt/golfind/server/golfind.db`
- **Logs Systemd**: `/var/log/syslog` ou `journalctl`
- **Frontend Build**: `/opt/golfind/dist`
- **Backend**: `/opt/golfind/server`
