FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

# O comando host é necessário para o Docker expor a porta corretamente
CMD ["npm", "run", "dev", "--", "--host"]
