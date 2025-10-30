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

// --- Helper for status enum mapping ---
const statusMap = {
  'Em Andamento': 'EM_ANDAMENTO',
  'Vencida': 'VENCIDA',
  'Encerrada': 'ENCERRADA',
  'Desclassificada': 'DESCLASSIFICADA',
};

const mapStatusToEnum = (statusString) => {
  return statusMap[statusString] || statusString;
};

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// --- ROTAS DE AUTENTICAÇÃO (PÚBLICAS) ---
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

// --- HEALTH CHECK ---
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

// --- GERENCIAMENTO DE USUÁRIOS ---
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: { id: true, name: true, username: true, createdAt: true },
      orderBy: { name: 'asc' },
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar usuários.' });
  }
});

app.post('/api/users', authenticateToken, async (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password) {
    return res.status(400).json({ error: 'Nome, nome de usuário e senha são obrigatórios.' });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { name, username, passwordHash },
      select: { id: true, name: true, username: true, createdAt: true },
    });
    res.status(201).json(newUser);
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'Nome de usuário já existe.' });
    }
    res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, username, password } = req.body;

  let dataToUpdate = { name, username };
  if (password) {
    dataToUpdate.passwordHash = await bcrypt.hash(password, 10);
  }

  try {
    const updatedUser = await prisma.user.update({
      where: { id },
      data: dataToUpdate,
      select: { id: true, name: true, username: true, createdAt: true },
    });
    res.json(updatedUser);
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'Nome de usuário já existe.' });
    }
    res.status(500).json({ error: 'Erro ao atualizar usuário.' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.user.delete({ where: { id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir usuário.' });
  }
});

// --- LICITAÇÕES ---
app.get('/api/licitacoes', authenticateToken, async (req, res) => {
  try {
    const licitacoes = await prisma.licitacaoDetalhada.findMany({
      orderBy: { lastUpdated: 'desc' }
    });
    res.json(licitacoes);
  } catch (error) {
    console.error("Get Licitacoes error:", error);
    res.status(500).json({ error: 'Erro ao buscar licitações.' });
  }
});

app.post('/api/licitacoes', authenticateToken, async (req, res) => {
  try {
    const { id, ...data } = req.body;
    if (data.status) {
      data.status = mapStatusToEnum(data.status);
    }
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
    if (data.status) {
      data.status = mapStatusToEnum(data.status);
    }
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

app.post('/api/restore-bids-backup', authenticateToken, async (req, res) => {
  const { licitacoes } = req.body;
  if (!Array.isArray(licitacoes)) {
    return res.status(400).json({ error: 'O corpo da requisição deve conter um array de "licitacoes".' });
  }

  try {
    await prisma.$transaction(async (tx) => {
      await tx.licitacaoDetalhada.deleteMany({});
      const dataToCreate = licitacoes.map(({ id, ...rest }) => ({
        ...rest,
        status: mapStatusToEnum(rest.status),
      }));
      await tx.licitacaoDetalhada.createMany({
        data: dataToCreate,
        skipDuplicates: true,
      });
    });
    res.status(200).json({ message: 'Backup das licitações restaurado com sucesso.' });
  } catch (error) {
    console.error("Restore Licitacoes error:", error);
    res.status(500).json({ error: 'Erro ao restaurar o backup de licitações.' });
  }
});

// --- CALENDÁRIO ---
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

app.post('/api/events/restore', authenticateToken, async (req, res) => {
  const { events } = req.body;
  if (!Array.isArray(events)) {
    return res.status(400).json({ error: 'O corpo da requisição deve ser um objeto { events: [] }.' });
  }
  try {
    await prisma.$transaction(async (tx) => {
      await tx.eventoCalendarioDetalhado.deleteMany({});
      const dataToCreate = events.map(({ id, ...rest }) => rest);
      if (dataToCreate.length > 0) {
        await tx.eventoCalendarioDetalhado.createMany({ data: dataToCreate });
      }
    });
    res.status(200).json({ message: 'Backup do calendário restaurado com sucesso.' });
  } catch (error) {
    console.error("Restore Events error:", error);
    res.status(500).json({ error: 'Erro ao restaurar o backup do calendário.' });
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
          orderBy: { nome: 'asc' }
        },
      },
      orderBy: { nome: 'asc' }
    });
    res.json(data);
  } catch (error) {
    console.error("Get Materiais error:", error);
    res.status(500).json({ error: 'Erro ao buscar dados de materiais.' });
  }
});

// NOVO: GET único de edital (frontend às vezes tenta buscar)
app.get('/api/editais/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const edital = await prisma.edital.findUnique({
      where: { id },
      include: {
        itens: true,
        saidas: true,
        empenhos: true,
        municipio: true,
      }
    });
    if (!edital) {
      return res.status(404).json({ error: 'Edital não encontrado.' });
    }
    res.json(edital);
  } catch (error) {
    console.error("Get Edital error:", error);
    res.status(500).json({ error: 'Erro ao buscar edital.' });
  }
});

/**
 * PUT /api/editais/:id
 * AGORA É INCREMENTAL:
 * - Atualiza só o que mudou
 * - Cria o que é novo (sem id)
 * - Remove só o que foi apagado no frontend
 * - NÃO dá mais drop geral nos itens/saídas/empenhos
 */
app.put('/api/editais/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { nome, itens = [], saidas = [], empenhos = [] } = req.body;

  try {
    const result = await prisma.$transaction(async (tx) => {
      // 1. Buscar o edital atual com tudo
      const existing = await tx.edital.findUnique({
        where: { id },
        include: {
          itens: true,
          saidas: true,
          empenhos: true,
        },
      });

      if (!existing) {
        throw new Error('Edital não encontrado.');
      }

      // ---------- ITENS ----------
      const existingItensById = new Map(
        (existing.itens || []).map((i) => [i.id, i])
      );
      const incomingItemIds = new Set(
        itens.filter((it) => it.id).map((it) => it.id)
      );

      // Itens a deletar (existem no banco mas não vieram do frontend)
      const itensToDelete = (existing.itens || [])
        .filter((it) => !incomingItemIds.has(it.id))
        .map((it) => it.id);

      if (itensToDelete.length > 0) {
        await tx.estoqueItem.deleteMany({
          where: { id: { in: itensToDelete } },
        });
      }

      // Itens a criar/atualizar
      for (const it of itens) {
        if (it.id && existingItensById.has(it.id)) {
          // update
          const { id: _ignore, ...data } = it;
          await tx.estoqueItem.update({
            where: { id: it.id },
            data: {
              descricao: data.descricao,
              marca: data.marca || '',
              unidade: data.unidade,
              quantidade: data.quantidade,
              valorUnitario: data.valorUnitario,
              valorTotal: data.valorTotal,
            },
          });
        } else {
          // create
          const { id: _ignore, ...data } = it;
          await tx.estoqueItem.create({
            data: {
              ...data,
              marca: data.marca || '',
              editalId: existing.id,
            },
          });
        }
      }

      // ---------- SAÍDAS ----------
      const existingSaidasById = new Map(
        (existing.saidas || []).map((s) => [s.id, s])
      );
      const incomingSaidasIds = new Set(
        saidas.filter((s) => s.id).map((s) => s.id)
      );

      const saidasToDelete = (existing.saidas || [])
        .filter((s) => !incomingSaidasIds.has(s.id))
        .map((s) => s.id);

      if (saidasToDelete.length > 0) {
        await tx.saidaItem.deleteMany({
          where: { id: { in: saidasToDelete } },
        });
      }

      for (const s of saidas) {
        if (s.id && existingSaidasById.has(s.id)) {
          const { id: _ignore, ...data } = s;
          await tx.saidaItem.update({
            where: { id: s.id },
            data: {
              itemIndex: data.itemIndex,
              descricao: data.descricao,
              marca: data.marca || '',
              quantidade: data.quantidade,
              valorUnitario: data.valorUnitario,
              valorTotal: data.valorTotal,
              data: data.data,
              notaFiscal: data.notaFiscal,
            },
          });
        } else {
          const { id: _ignore, ...data } = s;
          await tx.saidaItem.create({
            data: {
              ...data,
              marca: data.marca || '',
              editalId: existing.id,
            },
          });
        }
      }

      // ---------- EMPENHOS ----------
      const existingEmpById = new Map(
        (existing.empenhos || []).map((e) => [e.id, e])
      );
      const incomingEmpIds = new Set(
        empenhos.filter((e) => e.id).map((e) => e.id)
      );

      const empenhosToDelete = (existing.empenhos || [])
        .filter((e) => !incomingEmpIds.has(e.id))
        .map((e) => e.id);

      if (empenhosToDelete.length > 0) {
        await tx.empenho.deleteMany({
          where: { id: { in: empenhosToDelete } },
        });
      }

      for (const e of empenhos) {
        if (e.id && existingEmpById.has(e.id)) {
          const { id: _ignore, ...data } = e;
          await tx.empenho.update({
            where: { id: e.id },
            data: {
              dataPedido: data.dataPedido,
              numeroPedido: data.numeroPedido,
              numeroProcesso: data.numeroProcesso,
              dataNotaFiscal: data.dataNotaFiscal,
              valorNotaFiscal: data.valorNotaFiscal,
              empenhoPDF: data.empenhoPDF,
              notaFiscalPDF: data.notaFiscalPDF,
            },
          });
        } else {
          const { id: _ignore, ...data } = e;
          await tx.empenho.create({
            data: {
              ...data,
              editalId: existing.id,
            },
          });
        }
      }

      // Por fim, atualizar o nome do edital se mudou
      const updatedEdital = await tx.edital.update({
        where: { id: existing.id },
        data: {
          nome: nome ?? existing.nome,
        },
        include: {
          itens: true,
          saidas: true,
          empenhos: true,
        },
      });

      return updatedEdital;
    });

    res.json(result);
  } catch (error) {
    console.error("Update Edital (incremental) error:", error);
    res.status(500).json({ error: 'Erro ao atualizar dados do edital.' });
  }
});

// RESTORE (destrutivo) - mantido
app.post('/api/materiais/restore', authenticateToken, async (req, res) => {
  const dataToRestore = req.body;
  if (!Array.isArray(dataToRestore)) {
    return res.status(400).json({ error: 'O corpo da requisição deve conter um array de municípios.' });
  }

  try {
    await prisma.$transaction(async (tx) => {
      await tx.municipio.deleteMany({});

      for (const mun of dataToRestore) {
        await tx.municipio.create({
          data: {
            nome: mun.nome,
            editais: {
              create: (mun.editais || []).map(ed => ({
                nome: ed.nome,
                itens: {
                  create: (ed.itens || []).map(({ id, ...item }) => item)
                },
                saidas: {
                  create: (ed.saidas || []).map(({ id, ...saida }) => saida)
                },
                empenhos: {
                  create: (ed.empenhos || []).map(({ id, ...emp }) => emp)
                }
              }))
            }
          }
        });
      }
    });

    res.status(200).json({ message: 'Backup de materiais restaurado com sucesso.' });
  } catch (error) {
    console.error("Restore Materiais error:", error);
    res.status(500).json({ error: 'Erro ao restaurar o backup de materiais.' });
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

// --- ROTAS GRANULARES DE EDITAL (itens, saídas, empenhos) ---

// Atualizar apenas ITENS do edital
app.put('/api/editais/:id/itens', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { itens } = req.body; // espera array de itens
  if (!Array.isArray(itens)) {
    return res.status(400).json({ error: 'Campo "itens" precisa ser um array.' });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      // apaga itens atuais
      await tx.estoqueItem.deleteMany({ where: { editalId: id } });

      // recria itens
      await tx.edital.update({
        where: { id },
        data: {
          itens: {
            create: itens.map(({ id: _drop, ...item }) => item),
          },
        },
      });

      // retorna edital atualizado
      return tx.edital.findUnique({
        where: { id },
        include: {
          itens: true,
          saidas: true,
          empenhos: true,
        },
      });
    });

    res.json(result);
  } catch (error) {
    console.error('Update only itens error:', error);
    res.status(500).json({ error: 'Erro ao atualizar itens do edital.' });
  }
});

// Atualizar apenas SAÍDAS do edital
app.put('/api/editais/:id/saidas', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { saidas } = req.body;
  if (!Array.isArray(saidas)) {
    return res.status(400).json({ error: 'Campo "saidas" precisa ser um array.' });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      await tx.saidaItem.deleteMany({ where: { editalId: id } });

      await tx.edital.update({
        where: { id },
        data: {
          saidas: {
            create: saidas.map(({ id: _drop, ...saida }) => saída),
          },
        },
      });

      return tx.edital.findUnique({
        where: { id },
        include: {
          itens: true,
          saidas: true,
          empenhos: true,
        },
      });
    });

    res.json(result);
  } catch (error) {
    console.error('Update only saidas error:', error);
    res.status(500).json({ error: 'Erro ao atualizar saídas do edital.' });
  }
});

// Atualizar apenas EMPENHOS do edital
app.put('/api/editais/:id/empenhos', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { empenhos } = req.body;
  if (!Array.isArray(empenhos)) {
    return res.status(400).json({ error: 'Campo "empenhos" precisa ser um array.' });
  }

  try {
    const result = await prisma.$transaction(async (tx) => {
      await tx.empenho.deleteMany({ where: { editalId: id } });

      await tx.edital.update({
        where: { id },
        data: {
          empenhos: {
            create: empenhos.map(({ id: _drop, ...emp }) => emp),
          },
        },
      });

      return tx.edital.findUnique({
        where: { id },
        include: {
          itens: true,
          saidas: true,
          empenhos: true,
        },
      });
    });

    res.json(result);
  } catch (error) {
    console.error('Update only empenhos error:', error);
    res.status(500).json({ error: 'Erro ao atualizar empenhos do edital.' });
  }
});

// --- CONTROLE DE EPI (ENTREGAS) ---
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

app.post('/api/epi/restore', authenticateToken, async (req, res) => {
  const { entregas } = req.body;
  if (!Array.isArray(entregas)) {
    return res.status(400).json({ error: 'O corpo da requisição deve conter um array de "entregas".' });
  }

  try {
    await prisma.$transaction(async (tx) => {
      await tx.ePIEntrega.deleteMany({});

      const dataToCreate = entregas.map(({ id, ...rest }) => rest);

      if (dataToCreate.length > 0) {
        await tx.ePIEntrega.createMany({
          data: dataToCreate,
          skipDuplicates: true,
        });
      }
    });
    res.status(200).json({ message: 'Backup de EPI restaurado com sucesso.' });
  } catch (error) {
    console.error("Restore EPI error:", error);
    res.status(500).json({ error: 'Erro ao restaurar o backup de EPI.' });
  }
});

// --- CONTROLE DE ESTOQUE DE EPI ---
app.get('/api/epi-estoque', authenticateToken, async (req, res) => {
  try {
    const estoque = await prisma.ePIEstoqueItem.findMany({ orderBy: { name: 'asc' } });
    res.json(estoque);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar estoque de EPI.' });
  }
});

app.post('/api/epi-estoque', authenticateToken, async (req, res) => {
  const { name, qty } = req.body;
  try {
    const existingItem = await prisma.ePIEstoqueItem.findUnique({ where: { name } });
    if (existingItem) {
      const updatedItem = await prisma.ePIEstoqueItem.update({
        where: { name },
        data: { qty: existingItem.qty + qty },
      });
      res.json(updatedItem);
    } else {
      const newItem = await prisma.ePIEstoqueItem.create({ data: { name, qty } });
      res.status(201).json(newItem);
    }
  } catch (error) {
    res.status(500).json({ error: 'Erro ao adicionar item ao estoque de EPI.' });
  }
});

app.put('/api/epi-estoque/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { qty, manualOut, manualOutQty } = req.body;
  try {
    const updatedItem = await prisma.ePIEstoqueItem.update({
      where: { id },
      data: { qty, manualOut, manualOutQty },
    });
    res.json(updatedItem);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar item de estoque de EPI.' });
  }
});

app.delete('/api/epi-estoque/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.ePIEstoqueItem.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao remover item do estoque de EPI.' });
  }
});

app.post('/api/epi-estoque/restore', authenticateToken, async (req, res) => {
  const { estoque } = req.body;
  if (!Array.isArray(estoque)) {
    return res.status(400).json({ error: 'O corpo da requisição deve conter um array de "estoque".' });
  }
  try {
    await prisma.$transaction(async (tx) => {
      await tx.ePIEstoqueItem.deleteMany({});
      if (estoque.length > 0) {
        await tx.ePIEstoqueItem.createMany({
          data: estoque.map(({ id, ...rest }) => rest),
          skipDuplicates: true,
        });
      }
    });
    res.status(200).json({ message: 'Backup de estoque de EPI restaurado.' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao restaurar o backup de estoque de EPI.' });
  }
});

// --- SIMULAÇÕES SALVAS (MATERIAIS) ---
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
          create: (itens || []).map(({ id, ...item }) => item),
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

// --- COTAÇÕES ---
app.get('/api/cotacoes', authenticateToken, async (req, res) => {
  try {
    const cotacoes = await prisma.cotacao.findMany({ include: { itens: true }, orderBy: { data: 'desc' } });
    res.json(cotacoes);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar cotações.' });
  }
});

app.post('/api/cotacoes/import', authenticateToken, async (req, res) => {
  const { cotacoes } = req.body;
  if (!Array.isArray(cotacoes)) return res.status(400).json({ error: "Formato inválido." });
  try {
    const created = await prisma.$transaction(
      cotacoes.map(c => prisma.cotacao.create({
        data: {
          local: c.local,
          data: c.data,
          itens: {
            create: c.itens.map(({ id, ...item }) => item)
          }
        }
      }))
    );
    res.status(201).json(created);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao importar cotações.' });
  }
});

app.delete('/api/cotacoes/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.cotacao.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar cotação.' });
  }
});

// --- VALORES DE REFERÊNCIA ---
app.get('/api/valores-referencia', authenticateToken, async (req, res) => {
  try {
    const valores = await prisma.valorReferencia.findMany();
    res.json(valores);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar valores de referência.' });
  }
});

app.post('/api/valores-referencia', authenticateToken, async (req, res) => {
  const { id, produto, valor } = req.body;
  try {
    const upsertedValor = await prisma.valorReferencia.upsert({
      where: { id },
      update: { produto, valor },
      create: { id, produto, valor },
    });
    res.status(201).json(upsertedValor);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao salvar valor de referência.' });
  }
});

app.delete('/api/valores-referencia/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.valorReferencia.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar valor de referência.' });
  }
});

// --- SIMULAÇÕES DE COTAÇÃO ---
app.get('/api/simulacoes-cotacoes', authenticateToken, async (req, res) => {
  try {
    const simulacoes = await prisma.simulacaoCotacaoSalva.findMany({ include: { itens: true } });
    res.json(simulacoes);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar simulações de cotação.' });
  }
});

app.post('/api/simulacoes-cotacoes', authenticateToken, async (req, res) => {
  const { nome, data, itens } = req.body;
  try {
    const newSimulacao = await prisma.simulacaoCotacaoSalva.create({
      data: {
        nome,
        data,
        itens: {
          create: (itens || []).map(item => ({
            produto: item.produto,
            unidade: item.unidade,
            quantidade: item.quantidade,
            valorUnitario: item.valorUnitario,
            valorTotal: item.valorTotal,
            marca: item.marca,
            origemCotacaoId: item.cotacaoOrigem.id,
            origemCotacaoLocal: item.cotacaoOrigem.local,
            origemCotacaoData: item.cotacaoOrigem.data,
          }))
        }
      },
      include: { itens: true }
    });
    res.status(201).json(newSimulacao);
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Erro ao salvar simulação de cotação.' });
  }
});

app.delete('/api/simulacoes-cotacoes/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.simulacaoCotacaoSalva.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar simulação de cotação.' });
  }
});

// --- CALCULADORA ---
app.get('/api/calculadora', authenticateToken, async (req, res) => {
  try {
    const calculos = await prisma.calculadoraSalva.findMany({
      orderBy: { data: 'desc' }
    });
    res.json(calculos);
  } catch (error) {
    console.error("Get Calculadora error:", error);
    res.status(500).json({ error: 'Erro ao buscar cálculos salvos.' });
  }
});

app.post('/api/calculadora', authenticateToken, async (req, res) => {
  const { nome, custos } = req.body;
  if (!nome || !custos) {
    return res.status(400).json({ error: "Nome e objeto de custos são obrigatórios." });
  }
  try {
    const novoCalculo = await prisma.calculadoraSalva.create({
      data: {
        nome,
        custos
      }
    });
    res.status(201).json(novoCalculo);
  } catch (error) {
    console.error("Create Calculadora error:", error);
    res.status(500).json({ error: 'Erro ao salvar cálculo.' });
  }
});

app.delete('/api/calculadora/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.calculadoraSalva.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    console.error("Delete Calculadora error:", error);
    res.status(500).json({ error: 'Erro ao deletar cálculo.' });
  }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
