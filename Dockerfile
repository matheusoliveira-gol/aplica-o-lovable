# Estágio de Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copia apenas os arquivos de dependência primeiro para aproveitar o cache do Docker
COPY package*.json ./

# Instala dependências (usar ci é mais seguro para builds, ou install --legacy-peer-deps se der erro)
RUN npm install

# Copia o restante do código
COPY . .

# Argumentos de build (passados via terminal)
ARG VITE_SUPABASE_URL
ARG VITE_SUPABASE_ANON_KEY

# Define as variáveis de ambiente para o momento do build do Vite
ENV VITE_SUPABASE_URL=$VITE_SUPABASE_URL
ENV VITE_SUPABASE_ANON_KEY=$VITE_SUPABASE_ANON_KEY

# Executa o build (Se houver erro de TypeScript aqui, veja a observação abaixo)
RUN npm run build

# Estágio de Execução (Nginx)
FROM nginx:alpine

# Copia o arquivo de configuração que criamos no Passo 1
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copia os arquivos estáticos gerados pelo build (pasta dist)
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"
