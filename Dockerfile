# Estágio 1: Base com Node.js
# Trocamos 'alpine' por 'bullseye-slim' para melhor compatibilidade de bibliotecas
FROM node:20-bullseye-slim AS base

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
# Ele vai baixar o 'linux-gnu' engine automaticamente, que é compatível.
RUN npx prisma generate

# Expõe a porta que o servidor vai usar
EXPOSE 3001

# Comando para iniciar o servidor quando o contêiner rodar
CMD ["node", "server.js"]
