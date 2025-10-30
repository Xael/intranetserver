
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  const username = 'admincrb';
  const password = 'crb312@!';
  const name = 'Administrador';

  // Verifica se o usuário admin já existe
  const existingAdmin = await prisma.user.findUnique({
    where: { username },
  });

  if (existingAdmin) {
    console.log('Usuário admin já existe. Nenhuma ação necessária.');
    return;
  }

  // Se não existir, cria o usuário
  const passwordHash = await bcrypt.hash(password, 10);
  await prisma.user.create({
    data: {
      username,
      passwordHash,
      name,
      role: 'ADMIN',
    },
  });
  console.log('Usuário admin criado com sucesso!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
