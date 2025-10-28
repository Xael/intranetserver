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
    console.error("Register error:", error);
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
    console.error("Login error:", error);
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
    console.error("Get Licitacoes error:", error);
    res.status(500).json({ error: 'Erro ao buscar licitações.' });
  }
});

app.post('/api/licitacoes', authenticateToken, async (req, res) => {
  try {
    const { id, ...data } = req.body;
    const newLicitacao = await prisma.licitacaoDetalhada.create({ data });
    res.status(201).json(newLicitacao);
  } catch (error) {
    console.error("Create Licitacao error:", error);
    res.status(500).json({ error: 'Erro ao criar licitação.' });
  }
});

app.put('/api/licitacoes/:id', authenticateToken, async (req, res) => {
  try {
    const { id, ...data } = req.body;
    const updatedLicitacao = await prisma.licitacaoDetalhada.update({
      where: { id: req.params.id },
      data,
    });
    res.json(updatedLicitacao);
  } catch (error) {
    console.error("Update Licitacao error:", error);
    res.status(500).json({ error: 'Erro ao atualizar licitação.' });
  }
});

app.delete('/api/licitacoes/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.licitacaoDetalhada.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    console.error("Delete Licitacao error:", error);
    res.status(500).json({ error: 'Erro ao deletar licitação.' });
  }
});


// --- CALENDÁRIO (EVENTOS) ---
app.get('/api/events', authenticateToken, async (req, res) => {
    try {
        const events = await prisma.eventoCalendarioDetalhado.findMany();
        res.json(events);
    } catch (error) {
        console.error("Get Events error:", error);
        res.status(500).json({ error: 'Erro ao buscar eventos.' });
    }
});

app.post('/api/events', authenticateToken, async (req, res) => {
    try {
        const { id, ...data } = req.body;
        const newEvent = await prisma.eventoCalendarioDetalhado.create({ data });
        res.status(201).json(newEvent);
    } catch (error) {
        console.error("Create Event error:", error);
        res.status(500).json({ error: 'Erro ao criar evento.' });
    }
});

app.put('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        const { id, ...data } = req.body;
        const updatedEvent = await prisma.eventoCalendarioDetalhado.update({
            where: { id: req.params.id },
            data,
        });
        res.json(updatedEvent);
    } catch (error) {
        console.error("Update Event error:", error);
        res.status(500).json({ error: 'Erro ao atualizar evento.' });
    }
});

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.eventoCalendarioDetalhado.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        console.error("Delete Event error:", error);
        res.status(500).json({ error: 'Erro ao deletar evento.' });
    }
});


// --- CONTROLE DE MATERIAIS, EMPENHOS, ETC ---
app.get('/api/materiais', authenticateToken, async (req, res) => {
    try {
        const data = await prisma.municipio.findMany({
            include: {
                editais: {
                    include: {
                        itens: { orderBy: { id: 'asc' } },
                        saidas: { orderBy: { id: 'asc' } },
                        empenhos: { orderBy: { dataPedido: 'desc' } },
                    },
                },
            },
        });
        res.json(data);
    } catch (error) {
        console.error("Get Materiais error:", error);
        res.status(500).json({ error: 'Erro ao buscar dados de materiais.' });
    }
});

app.put('/api/editais/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { nome, municipioId, itens, saidas, empenhos } = req.body;
    try {
        // Usando uma transação para garantir a atomicidade da operação
        const result = await prisma.$transaction(async (tx) => {
            // 1. Limpa relações existentes
            await tx.estoqueItem.deleteMany({ where: { editalId: id } });
            await tx.saidaItem.deleteMany({ where: { editalId: id } });
            await tx.empenho.deleteMany({ where: { editalId: id } });
            
            // 2. Atualiza o edital e recria as relações
            const updatedEdital = await tx.edital.update({
                where: { id },
                data: {
                    nome,
                    municipioId,
                    itens: { create: itens.map(({ id, ...item }) => item) },
                    saidas: { create: saidas.map(({ id, ...saida }) => saida) },
                    empenhos: { create: (empenhos || []).map(({ id, ...emp }) => emp) },
                },
                include: { itens: true, saidas: true, empenhos: true },
            });
            return updatedEdital;
        });
        res.json(result);
    } catch (error) {
        console.error("Update Edital error:", error);
        res.status(500).json({ error: 'Erro ao atualizar dados do edital.' });
    }
});

app.post('/api/municipios', authenticateToken, async (req, res) => {
  const { nome } = req.body;
  try {
    const existing = await prisma.municipio.findFirst({ where: { nome: { equals: nome, mode: 'insensitive' } } });
    if (existing) return res.status(409).json({ error: "Município já existe." });
    
    const municipio = await prisma.municipio.create({ data: { nome } });
    res.status(201).json(municipio);
  } catch (error) {
    console.error("Create Municipio error:", error);
    res.status(500).json({ error: 'Erro ao criar município.' });
  }
});

app.delete('/api/municipios/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.municipio.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    console.error("Delete Municipio error:", error);
    res.status(500).json({ error: 'Erro ao deletar município.' });
  }
});

app.post('/api/municipios/:municipioId/editais', authenticateToken, async (req, res) => {
  const { municipioId } = req.params;
  const { nome } = req.body;
  try {
    const edital = await prisma.edital.create({ data: { nome, municipioId } });
    res.status(201).json(edital);
  } catch (error) {
    console.error("Create Edital error:", error);
    res.status(500).json({ error: 'Erro ao criar edital.' });
  }
});

app.delete('/api/editais/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.edital.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        console.error("Delete Edital error:", error);
        res.status(500).json({ error: 'Erro ao deletar edital.' });
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
        console.error("Get EPI error:", error);
        res.status(500).json({ error: 'Erro ao buscar entregas de EPI.' });
    }
});

app.post('/api/epi', authenticateToken, async (req, res) => {
    try {
        const { id, ...data } = req.body;
        const novaEntrega = await prisma.ePIEntrega.create({ data });
        res.status(201).json(novaEntrega);
    } catch (error) {
        console.error("Create EPI error:", error);
        res.status(500).json({ error: 'Erro ao registrar entrega de EPI.' });
    }
});

app.delete('/api/epi/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.ePIEntrega.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        console.error("Delete EPI error:", error);
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
        console.error("Get Simulacoes error:", error);
        res.status(500).json({ error: 'Erro ao buscar simulações salvas.' });
    }
});

app.post('/api/simulacoes', authenticateToken, async (req, res) => {
    const { id, itens, ...simulacaoData } = req.body;
    try {
        const novaSimulacao = await prisma.simulacaoSalva.create({
            data: {
                ...simulacaoData,
                itens: {
                    create: itens.map(({id, ...item}) => item),
                },
            },
            include: { itens: true }
        });
        res.status(201).json(novaSimulacao);
    } catch (error) {
        console.error("Create Simulacao error:", error);
        res.status(500).json({ error: 'Erro ao salvar simulação.' });
    }
});

app.delete('/api/simulacoes/:id', authenticateToken, async (req, res) => {
    try {
        await prisma.simulacaoSalva.delete({ where: { id: req.params.id } });
        res.status(204).send();
    } catch (error) {
        console.error("Delete Simulacao error:", error);
        res.status(500).json({ error: 'Erro ao deletar simulação.' });
    }
});


// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
