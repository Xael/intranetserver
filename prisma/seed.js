// prisma/seed.js
const { PrismaClient, Role } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  // dados do admin padrão
  const username = 'admincrb';
  const password = 'crb312@!';
  const name = 'Administrador';

  // verifica se já existe
  const existingAdmin = await prisma.user.findUnique({
    where: { username },
  });

  if (existingAdmin) {
    console.log('Usuário admin já existe. Nenhuma ação necessária.');
    return;
  }

  // cria o hash
  const passwordHash = await bcrypt.hash(password, 10);

  // cria o usuário
  await prisma.user.create({
    data: {
      username,
      passwordHash,
      name,
      // aqui é o ponto importante: usar o enum do Prisma
      role: Role.ADMIN, // ou 'ADMIN' se você preferir string, mas Role.ADMIN é mais seguro
    },
  });

  console.log('Usuário admin criado com sucesso!');
}

main()
  .catch((e) => {
    console.error('Erro ao rodar seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
