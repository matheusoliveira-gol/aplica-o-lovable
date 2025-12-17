# Estágio 1: Build do React/Vite
FROM node:18-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Estágio 2: Servidor Nginx para rodar o site
FROM nginx:alpine
# Copia os arquivos gerados no build para a pasta do Nginx
COPY --from=build /app/dist /usr/share/nginx/html
# Copia nossa configuração personalizada do Nginx
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
