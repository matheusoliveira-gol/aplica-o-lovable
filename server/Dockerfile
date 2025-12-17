FROM node:18-alpine

# Instala dependências necessárias para compilar o better-sqlite3 e bcrypt
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copia apenas os arquivos de dependência primeiro (para cache eficiente)
COPY package*.json ./

# Instala as dependências
RUN npm install

# Copia o restante do código do backend
COPY . .

# Expõe a porta que você usa no index.js
EXPOSE 3001

# Inicia o servidor
CMD ["node", "index.js"]
