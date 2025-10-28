const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3001;

// É altamente recomendável mover esta chave para uma variável de ambiente (.env)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-is-long-and-secure';

// Middleware
app.use(cors()); // Habilita Cross-Origin Resource Sharing
app.use(express.json({ limit: '10mb' })); // Aumenta o limite para upload de arquivos (base64)

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // Não autorizado se não houver token
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Proibido se o token for inválido
    }
    req.user = user;
    next();
  });
};


// --- ROTAS DE AUTENTICAÇÃO (PÚBLICAS) ---

// Rota para registrar um novo usuário
app.post('/api/auth/register', async (req, res) => {
  const { username, password, name } = req.body;
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) {
      return res.status(409).json({ error: 'Nome de usuário já existe.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { username, passwordHash, name },
    });
    res.status(201).json({ id: user.id, username: user.username, name: user.name });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao registrar usuário.' });
  }
});

// Rota para login de usuário
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { username: user.username, name: user.name } });
  } catch (error) {
    res.status(500).json({ error: 'Erro no servidor durante o login.' });
  }
});


// --- ROTAS PROTEGIDAS DA API ---
// Todas as rotas abaixo exigem um token de autenticação válido

// Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});


// --- LICITAÇÕES (STATUS) ---
app.get('/api/licitacoes', authenticateToken, async (req, res) => {
  try {
    const licitacoes = await prisma.licitacaoDetalhada.findMany();
    res.json(licitacoes);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar licitações.' });
  }
});

app.post('/api/licitacoes', authenticateToken, async (req, res) => {
  try {
    const newLicitacao = await prisma.licitacaoDetalhada.create({ data: req.body });
    res.status(201).json(newLicitacao);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar licitação.' });
  }
});

app.put('/api/licitacoes/:id', authenticateToken, async (req, res) => {
  try {
    const updatedLicitacao = await prisma.licitacaoDetalhada.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json(updatedLicitacao);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar licitação.' });
  }
});

app.delete('/api/licitacoes/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.licitacaoDetalhada.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar licitação.' });
  }
});


// --- CALENDÁRIO (EVENTOS) ---
app.get('/api/events', authenticateToken, async (req, res) => {
    try {
        const events = await prisma.eventoCalendarioDetalhado.findMany();
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar eventos.' });
    }
});

app.post('/api/events', authenticateToken, async (req, res) => {
    try {
        const newEvent = await prisma.eventoCalendarioDetalhado.create({ data: req.body });
        res.status(201).json(newEvent);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar evento.' });
    }
});

app.put('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        const updatedEvent = await prisma.eventoCalendarioDetalhado.update({
            where: { id: req.params.id },
            data: req.body,
        });
        res.json(updatedEvent);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar evento.' });
    }
});

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.eventoCalendarioDetalhado.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar evento.' });
    }
});


// --- CONTROLE DE MATERIAIS, EMPENHOS, ETC ---
app.get('/api/materiais', authenticateToken, async (req, res) => {
    try {
        // Retorna a estrutura completa de municípios, editais, itens, saídas e empenhos
        const data = await prisma.municipio.findMany({
            include: {
                editais: {
                    include: {
                        itens: true,
                        saidas: true,
                        empenhos: true,
                    },
                },
            },
        });
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar dados de materiais.' });
    }
});

// Rota para substituir todos os dados de materiais (usado para restaurar backup)
app.post('/api/materiais/restore', authenticateToken, async (req, res) => {
    const data = req.body;
    try {
        // Esta é uma operação destrutiva, tenha cuidado.
        // Apaga tudo e recria a partir do backup.
        await prisma.$transaction([
            prisma.saidaItem.deleteMany(),
            prisma.estoqueItem.deleteMany(),
            prisma.empenho.deleteMany(),
            prisma.edital.deleteMany(),
            prisma.municipio.deleteMany(),
            // Recria os municípios
            ...data.map(mun => prisma.municipio.create({
                data: {
                    nome: mun.nome,
                    editais: {
                        create: mun.editais.map(ed => ({
                            nome: ed.nome,
                            itens: { create: ed.itens.map(({id, ...item}) => item) },
                            saidas: { create: ed.saidas.map(({id, ...saida}) => saida) },
                            empenhos: { create: (ed.empenhos || []).map(({id, ...emp}) => emp) }
                        }))
                    }
                }
            }))
        ]);
        res.status(200).json({ message: 'Backup restaurado com sucesso.' });
    } catch (error) {
        console.error("Erro na transação de restauração:", error);
        res.status(500).json({ error: 'Erro ao restaurar o backup.' });
    }
});

// Atualiza um edital inteiro. Útil para quando múltiplas mudanças ocorrem (add item, add saida, etc)
// O frontend pode enviar o objeto do edital atualizado.
app.put('/api/editais/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { itens, saidas, empenhos, ...editalData } = req.body;
    try {
        await prisma.edital.update({
            where: { id },
            data: {
                ...editalData,
                itens: {
                    deleteMany: {},
                    create: itens.map(({id, ...item}) => item)
                },
                saidas: {
                    deleteMany: {},
                    create: saidas.map(({id, ...saida}) => saida)
                },
                empenhos: {
                    deleteMany: {},
                    create: (empenhos || []).map(({id, ...emp}) => emp)
                }
            }
        });
        const updatedEdital = await prisma.edital.findUnique({ where: { id }, include: { itens: true, saidas: true, empenhos: true } });
        res.json(updatedEdital);
    } catch (error) {
        console.error("Erro ao atualizar edital:", error)
        res.status(500).json({ error: 'Erro ao atualizar dados do edital.' });
    }
});


// --- CONTROLE DE EPI ---
app.get('/api/epi', authenticateToken, async (req, res) => {
    try {
        const entregas = await prisma.ePIEntrega.findMany({
            orderBy: { dataEntrega: 'desc' }
        });
        res.json(entregas);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar entregas de EPI.' });
    }
});

app.post('/api/epi', authenticateToken, async (req, res) => {
    try {
        const novaEntrega = await prisma.ePIEntrega.create({ data: req.body });
        res.status(201).json(novaEntrega);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao registrar entrega de EPI.' });
    }
});

app.delete('/api/epi/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.ePIEntrega.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar entrega de EPI.' });
    }
});


// --- SIMULAÇÕES SALVAS ---
app.get('/api/simulacoes', authenticateToken, async (req, res) => {
    try {
        const simulacoes = await prisma.simulacaoSalva.findMany({
            include: { itens: true }
        });
        res.json(simulacoes);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar simulações salvas.' });
    }
});

app.post('/api/simulacoes', authenticateToken, async (req, res) => {
    const { itens, ...simulacaoData } = req.body;
    try {
        const novaSimulacao = await prisma.simulacaoSalva.create({
            data: {
                ...simulacaoData,
                itens: {
                    create: itens,
                },
            },
            include: { itens: true }
        });
        res.status(201).json(novaSimulacao);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao salvar simulação.' });
    }
});

app.delete('/api/simulacoes/:id', authenticateToken, async (req, res) => {
    try {
        // Prisma cascade delete irá remover os 'SimulacaoItem' associados
        await prisma.simulacaoSalva.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar simulação.' });
    }
});


// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
