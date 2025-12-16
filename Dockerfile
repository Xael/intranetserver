# Estágio 1: Base com Node.js
# 'bullseye-slim' para melhor compatibilidade de bibliotecas
FROM node:20-bullseye-slim AS base

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# ✅ Instala CA tools e adiciona a raiz ICP-Brasil v10 ao trust store do Linux
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssl \
 && rm -rf /var/lib/apt/lists/*

# ✅ Baixa a Raiz ICP-Brasil v10 (DER) e converte pra PEM, registra no sistema
RUN curl -fsSL "http://acraiz.icpbrasil.gov.br/ICP-Brasilv10.crt" -o /tmp/icpbrv10.crt \
 && openssl x509 -inform DER -in /tmp/icpbrv10.crt -out /usr/local/share/ca-certificates/icpbr-root-v10.pem \
 && update-ca-certificates \
 && rm -f /tmp/icpbrv10.crt

# ✅ Faz o Node confiar explicitamente nessa CA extra (resolve axios/https)
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/icpbr-root-v10.pem

# Copia os arquivos de definição de dependências
COPY package*.json ./

# Instala SOMENTE as dependências de produção.
RUN npm install --production

# Copia o restante do código da aplicação, incluindo o schema do Prisma
COPY . .

# *** PASSO CRUCIAL PARA O PRISMA ***
RUN npx prisma generate

# Expõe a porta que o servidor vai usar
EXPOSE 3001

# Comando para iniciar o servidor quando o contêiner rodar
CMD ["node", "server.js"]
