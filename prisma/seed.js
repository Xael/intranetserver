// prisma/seed.js
const { PrismaClient, Role } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  const username = 'admincrb';
  const password = 'crb312@!';
  const name = 'Administrador';

  const passwordHash = await bcrypt.hash(password, 10);

  // upsert garante que, se já existir, atualiza
  const admin = await prisma.user.upsert({
    where: { username },
    update: {
      name,
      role: Role.ADMIN,
      passwordHash,
    },
    create: {
      username,
      name,
      passwordHash,
      role: Role.ADMIN,
    },
  });

  console.log('Usuário admin pronto:', admin.username);
}

main()
  .catch((e) => {
    console.error('Erro ao rodar seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
