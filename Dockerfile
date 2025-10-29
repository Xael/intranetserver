# Estágio 1: Base com Node.js
FROM node:20-alpine AS base

# *** ADICIONE ESTA LINHA ***
# Instala a dependência de compatibilidade do OpenSSL 1.1 que o Prisma precisa
RUN apk add --no-cache openssl1.1-compat

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia os arquivos de definição de dependências
COPY package*.json ./

# Instala SOMENTE as dependências de produção.
RUN npm install --production

# Copia o restante do código da aplicação, incluindo o schema do Prisma
COPY . .

# *** PASSO CRUCIAL PARA O PRISMA ***
# Gera o Prisma Client com base no schema.
RUN npx prisma generate

# Expõe a porta que o servidor vai usar
EXPOSE 3001

# Comando para iniciar o servidor quando o contêiner rodar
CMD ["node", "server.js"]
