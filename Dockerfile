# Estágio 1: Base com Node.js
# Usamos a imagem oficial do Node.js 20 na versão 'alpine' (super leve)
FROM node:20-alpine AS base

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia os arquivos de definição de dependências
# Isso aproveita o cache do Docker. Se esses arquivos não mudarem,
# o 'npm install' não precisa rodar de novo.
COPY package*.json ./

# Instala SOMENTE as dependências de produção.
# 'nodemon' e 'prisma' (CLI) são devDependencies e não precisam ir para produção.
RUN npm install --production

# Copia o restante do código da aplicação, incluindo o schema do Prisma
COPY . .

# *** PASSO CRUCIAL PARA O PRISMA ***
# Gera o Prisma Client com base no schema.
# Isso é necessário para que a aplicação consiga se comunicar com o banco de dados.
RUN npx prisma generate

# Expõe a porta que o servidor vai usar
EXPOSE 3001

# Comando para iniciar o servidor quando o contêiner rodar
CMD ["node", "server.js"]
