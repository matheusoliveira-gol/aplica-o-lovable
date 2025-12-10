# Estágio 1: Build (Construção)
FROM node:20-alpine AS builder

WORKDIR /app

# Copia os arquivos de dependência
COPY package*.json ./
RUN npm install

# Copia o código do projeto
COPY . .

# --- CHAVES DO SUPABASE DEFINIDAS AQUI ---
ENV VITE_SUPABASE_URL="https://klrtqqxrdijporxqdziw.supabase.co"
ENV VITE_SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtscnRxcXhyZGlqcG9yeHFkeml3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE2NjE3NDMsImV4cCI6MjA3NzIzNzc0M30.2meBUmwtvDGUyJ8GWEZNvrL7CLEMnA2Q8UqZIGsfNpY"
# -----------------------------------------

# Gera a pasta dist/
RUN npm run build

# Estágio 2: Servidor (Nginx)
FROM nginx:alpine

# Copia o site pronto
COPY --from=builder /app/dist /usr/share/nginx/html

# Configuração do Nginx (Anti-Erro 404)
RUN echo 'server { \
    listen 80; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html index.htm; \
        try_files $uri $uri/ /index.html; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
