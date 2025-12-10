# GolFind Server - Instalação em Linux

## Pré-requisitos
- Node.js 18+ instalado
- Sistema Linux (Ubuntu/Debian/CentOS)

## Instalação Rápida

### 1. Instalar Node.js (se necessário)
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# CentOS/RHEL
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo yum install -y nodejs
```

### 2. Preparar o Servidor
```bash
# Navegar até a pasta do servidor
cd server

# Instalar dependências
npm install

# Iniciar o servidor
npm start
```

O servidor estará rodando na porta 3001.

### 3. Fazer Build do Frontend
```bash
# Na raiz do projeto
npm run build

# Servir os arquivos estáticos (instalar serve se necessário)
npm install -g serve
serve -s dist -l 8080
```

### 4. Acessar pela Rede Local
Descubra o IP do servidor:
```bash
ip addr show
# ou
hostname -I
```

Os usuários da rede podem acessar:
- Frontend: `http://[IP_DO_SERVIDOR]:8080`
- API: `http://[IP_DO_SERVIDOR]:3001`

## Configuração como Serviço Systemd (Opcional)

### Backend
Criar arquivo `/etc/systemd/system/golfind-server.service`:
```ini
[Unit]
Description=GolFind Backend Server
After=network.target

[Service]
Type=simple
User=seu_usuario
WorkingDirectory=/caminho/para/golfind/server
ExecStart=/usr/bin/node index.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Frontend
Criar arquivo `/etc/systemd/system/golfind-frontend.service`:
```ini
[Unit]
Description=GolFind Frontend Server
After=network.target

[Service]
Type=simple
User=seu_usuario
WorkingDirectory=/caminho/para/golfind
ExecStart=/usr/bin/npx serve -s dist -l 8080
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Ativar os serviços
```bash
sudo systemctl daemon-reload
sudo systemctl enable golfind-server
sudo systemctl enable golfind-frontend
sudo systemctl start golfind-server
sudo systemctl start golfind-frontend
```

## Usando Nginx (Produção Recomendada)

Instalar nginx:
```bash
sudo apt-get install nginx  # Ubuntu/Debian
sudo yum install nginx      # CentOS/RHEL
```

Configurar `/etc/nginx/sites-available/golfind`:
```nginx
server {
    listen 80;
    server_name [IP_DO_SERVIDOR];

    # Frontend
    location / {
        root /caminho/para/golfind/dist;
        try_files $uri $uri/ /index.html;
    }

    # API Backend
    location /api {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Ativar:
```bash
sudo ln -s /etc/nginx/sites-available/golfind /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Firewall
Liberar as portas necessárias:
```bash
# UFW (Ubuntu)
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 3001/tcp

# Firewalld (CentOS)
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=3001/tcp
sudo firewall-cmd --reload
```

## Credenciais Padrão
- **Email**: admin@golfind.com
- **Senha**: admin123

## Backup do Banco de Dados
O arquivo do banco SQLite fica em: `server/golfind.db`

Para backup:
```bash
cp server/golfind.db server/golfind.db.backup
```

Para agendamento automático (crontab):
```bash
# Executar diariamente às 2h da manhã
0 2 * * * cp /caminho/para/golfind/server/golfind.db /backup/golfind.db.$(date +\%Y\%m\%d)
```
