const { parseString } = require('xml2js');
const { promisify } = require('util');
const parseXml = promisify(parseString);
// REMOVIDO: const NFeService = require('./services/NFeService'); 
// A classe NFeService agora está definida internamente abaixo para evitar erros de Docker.

const path = require('path');
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- NOVOS IMPORTS NECESSÁRIOS PARA NFE ---
const https = require('https');
const axios = require('axios');
const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');
const { create } = require('xmlbuilder2');

const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3001;

// É altamente recomendável mover esta chave para uma variável de ambiente (.env)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-is-long-and-secure';

// --- CLASSE NFeService (EMBUTIDA PARA CORRIGIR ERRO DE MODULE NOT FOUND) ---
class NFeService {
    constructor(pfxBuffer, senhaCertificado) {
        if (!pfxBuffer || !senhaCertificado) {
            throw new Error("Certificado ou senha não fornecidos.");
        }

        this.pfxBuffer = pfxBuffer;
        this.senha = senhaCertificado;

        try {
            // Extrair chave privada para assinatura
            const p12Asn1 = forge.asn1.fromDer(this.pfxBuffer.toString('binary'));
            const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, this.senha);
            const keyData = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag][0];
            this.privateKeyPem = forge.pki.privateKeyToPem(keyData.key);
        } catch (e) {
            throw new Error("Senha do certificado incorreta ou arquivo inválido.");
        }

        // Agente HTTPS para conexão mútua com a SEFAZ
        this.httpsAgent = new https.Agent({
            pfx: this.pfxBuffer,
            passphrase: this.senha,
            rejectUnauthorized: false
        });
    }

    generateXML(data) {
        const now = new Date();
        const dhEmi = new Date(now.getTime() - (now.getTimezoneOffset() * 60000)).toISOString().slice(0, 19) + '-03:00';

        const nfe = {
            NFe: {
                '@xmlns': 'http://www.portalfiscal.inf.br/nfe',
                infNFe: {
                    '@Id': `NFe${data.chaveAcesso}`,
                    '@versao': '4.00',
                    ide: {
                        cUF: 35, // SP (Ajustar conforme estado do emitente)
                        cNF: data.numero,
                        natOp: 'VENDA DE MERCADORIA',
                        mod: 55,
                        serie: data.serie,
                        nNF: data.numero,
                        dhEmi: dhEmi,
                        tpNF: 1,
                        idDest: 1,
                        cMunFG: data.emitente.endereco.codigoIbge,
                        tpImp: 1,
                        tpEmis: 1,
                        cDV: data.chaveAcesso ? data.chaveAcesso.slice(-1) : '0',
                        tpAmb: 2, // 2 = Homologação
                        finNFe: 1,
                        indFinal: 1,
                        indPres: 1,
                        procEmi: 0,
                        verProc: 'APP_NFE_NODE'
                    },
                    emit: {
                        CNPJ: data.emitente.cnpj.replace(/\D/g, ''),
                        xNome: data.emitente.razaoSocial,
                        enderEmit: {
                            xLgr: data.emitente.endereco.logradouro,
                            nro: data.emitente.endereco.numero,
                            xBairro: data.emitente.endereco.bairro,
                            cMun: data.emitente.endereco.codigoIbge,
                            xMun: data.emitente.endereco.municipio,
                            UF: data.emitente.endereco.uf,
                            CEP: data.emitente.endereco.cep,
                            cPais: 1058,
                            xPais: 'BRASIL'
                        },
                        IE: data.emitente.inscricaoEstadual.replace(/\D/g, ''),
                        CRT: data.emitente.crt
                    },
                    dest: {
                        CNPJ: data.destinatario.cnpj.replace(/\D/g, ''),
                        xNome: data.destinatario.razaoSocial,
                        enderDest: {
                            xLgr: data.destinatario.endereco.logradouro,
                            nro: data.destinatario.endereco.numero,
                            xBairro: data.destinatario.endereco.bairro,
                            cMun: data.destinatario.endereco.codigoIbge,
                            xMun: data.destinatario.endereco.municipio,
                            UF: data.destinatario.endereco.uf,
                            CEP: data.destinatario.endereco.cep,
                            cPais: 1058,
                            xPais: 'BRASIL'
                        },
                        indIEDest: 9
                    },
                    det: data.produtos.map((prod, i) => ({
                        '@nItem': i + 1,
                        prod: {
                            cProd: prod.codigo,
                            cEAN: "SEM GTIN",
                            xProd: prod.descricao,
                            NCM: prod.ncm,
                            CFOP: prod.cfop,
                            uCom: prod.unidade,
                            qCom: prod.quantidade,
                            vUnCom: prod.valorUnitario.toFixed(4),
                            vProd: prod.valorTotal.toFixed(2),
                            cEANTrib: "SEM GTIN",
                            uTrib: prod.unidade,
                            qTrib: prod.quantidade,
                            vUnTrib: prod.valorUnitario.toFixed(4),
                            indTot: 1
                        },
                        imposto: {
                            ICMS: { ICMSSN102: { orig: 0, CSOSN: '102' } },
                            PIS: { PISNT: { CST: '07' } },
                            COFINS: { COFINSNT: { CST: '07' } }
                        }
                    })),
                    total: {
                        ICMSTot: {
                            vBC: '0.00', vICMS: '0.00', vICMSDeson: '0.00',
                            vFCP: '0.00', vBCST: '0.00', vST: '0.00',
                            vFCPST: '0.00', vFCPSTRet: '0.00',
                            vProd: data.totais.vProd.toFixed(2),
                            vFrete: '0.00', vSeg: '0.00', vDesc: '0.00',
                            vII: '0.00', vIPI: '0.00', vIPIDevol: '0.00',
                            vPIS: '0.00', vCOFINS: '0.00', vOutro: '0.00',
                            vNF: data.totais.vNF.toFixed(2)
                        }
                    },
                    transp: { modFrete: 9 }
                }
            }
        };

        return create(nfe).end({ prettyPrint: false });
    }

    signXML(xml) {
        const sig = new SignedXml();
        sig.addReference("//*[local-name(.)='infNFe']",
            ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
            "http://www.w3.org/2000/09/xmldsig#sha1");
        
        sig.signingKey = this.privateKeyPem;
        sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        
        sig.computeSignature(xml);
        return sig.getSignedXml();
    }

    async transmit(xmlAssinado) {
        const envelope = `
            <soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
                <soap12:Header>
                    <nfeCabecMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4"><cUF>35</cUF><versaoDados>4.00</versaoDados></nfeCabecMsg>
                </soap12:Header>
                <soap12:Body>
                    <nfeDadosMsg xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4">${xmlAssinado}</nfeDadosMsg>
                </soap12:Body>
            </soap12:Envelope>`;

        // URL SP Homologação
        const url = 'https://homologacao.nfe.fazenda.sp.gov.br/ws/nfeautorizacao4.asmx';

        try {
            const res = await axios.post(url, envelope, {
                headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
                httpsAgent: this.httpsAgent
            });
            return res.data;
        } catch (error) {
            throw new Error(`Erro conexão SEFAZ: ${error.message}`);
        }
    }
}

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

    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { username: user.username, name: user.name, role: user.role } });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: 'Erro no servidor durante o login.' });
  }
});

// --- HEALTH CHECK ---
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

// --- CONFIGURAÇÕES DO SISTEMA (GLOBAL) ---
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    // Tenta buscar a configuração global. Se não existir, cria o padrão.
    let settings = await prisma.systemSettings.findUnique({ where: { id: 'global' } });
    
    if (!settings) {
      settings = await prisma.systemSettings.create({
        data: {
          id: 'global',
          nfeEnabled: true // Padrão ligado
        }
      });
    }
    res.json(settings);
  } catch (error) {
    console.error("Erro ao buscar configurações:", error);
    res.status(500).json({ error: "Erro ao buscar configurações do sistema." });
  }
});

app.put('/api/settings', authenticateToken, async (req, res) => {
  try {
    // Apenas ADMIN pode alterar configurações globais
    if (req.user.role !== 'ADMIN') {
        return res.status(403).json({ error: "Acesso negado. Apenas administradores podem alterar configurações do sistema." });
    }

    const { nfeEnabled } = req.body;
    
    const settings = await prisma.systemSettings.upsert({
      where: { id: 'global' },
      update: { nfeEnabled },
      create: { id: 'global', nfeEnabled }
    });
    
    res.json(settings);
  } catch (error) {
    console.error("Erro ao atualizar configurações:", error);
    res.status(500).json({ error: "Erro ao atualizar configurações." });
  }
});

// --- GERENCIAMENTO DE USUÁRIOS ---
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const usersFromDb = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
        username: true,
        createdAt: true,
        role: true,
      },
      orderBy: { name: 'asc' },
    });

    // garante role para registros antigos
    const users = usersFromDb.map((u) => ({
      ...u,
      role: u.role || 'OPERACIONAL',
    }));

    res.json(users);
  } catch (error) {
    console.error('Erro em GET /api/users:', error);
    res.status(500).json({ error: 'Erro ao buscar usuários.' });
  }
});


app.post('/api/users', authenticateToken, async (req, res) => {
  const { name, username, password, role } = req.body;
  if (!name || !username || !password) {
    return res.status(400).json({ error: 'Nome, nome de usuário e senha são obrigatórios.' });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { name, username, passwordHash, role: role || 'OPERACIONAL' },
      select: { id: true, name: true, username: true, createdAt: true, role: true },
    });
    res.status(201).json(newUser);
  } catch (error) {
    console.error("Erro detalhado em POST /api/users:", error);
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'Nome de usuário já existe.' });
    }
    res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, username, password, role } = req.body;

  try {
    const dataToUpdate = { name, username, role };
    if (password) {
      dataToUpdate.passwordHash = await bcrypt.hash(password, 10);
    }

    const updatedUser = await prisma.user.update({
      where: { id },
      data: dataToUpdate,
      select: { id: true, name: true, username: true, createdAt: true, role: true },
    });
    res.json(updatedUser);
  } catch (error) {
    console.error("Erro detalhado em PUT /api/users/:id:", error);
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'Nome de usuário já existe.' });
    } else if (error.code === 'P2025') {
       return res.status(404).json({ error: 'Usuário não encontrado.' });
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
    console.error("Erro detalhado em DELETE /api/users/:id:", error);
     if (error.code === 'P2025') {
       return res.status(404).json({ error: 'Usuário não encontrado.' });
    }
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

// ==========================================
// --- CALENDÁRIO (Rotas Corrigidas) ---
// ==========================================

// GET: Buscar eventos
app.get('/api/events', authenticateToken, async (req, res) => {
  try {
    const events = await prisma.eventoCalendarioDetalhado.findMany();
    // O frontend espera "date" ou "start", o banco tem "start".
    // Vamos garantir que o frontend receba o que precisa.
    const formatted = events.map(e => ({
        ...e,
        date: e.start // Cria o alias que o frontend antigo pode estar esperando
    }));
    res.json(formatted);
  } catch (error) {
    console.error("Get Events error:", error);
    res.status(500).json({ error: 'Erro ao buscar eventos.' });
  }
});

// POST: Criar evento
app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    // AQUI ESTAVA O ERRO: O front manda 'date', mas o banco não tem essa coluna.
    // Usamos desestruturação para remover 'id' e 'date' do objeto antes de salvar.
    const { id, date, ...data } = req.body;

    const newEvent = await prisma.eventoCalendarioDetalhado.create({
      data: {
        ...data,
        // Garante que o status tenha valor padrão se vier vazio
        documentationStatus: data.documentationStatus || 'PENDENTE',
      },
    });
    res.status(201).json(newEvent);
  } catch (error) {
    console.error("Create Event error:", error);
    // Log detalhado para te ajudar a ver qual campo está falhando
    res.status(500).json({ error: 'Erro ao criar evento. Verifique se o banco foi atualizado (npx prisma db push).' });
  }
});

// PUT: Atualizar evento
app.put('/api/events/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    // Removemos 'id', '_id' e 'date' para evitar conflitos no Prisma
    const { id: _, _id, date, ...data } = req.body;

    const updatedEvent = await prisma.eventoCalendarioDetalhado.update({
      where: { id },
      data: {
        ...data,
        documentationStatus: data.documentationStatus || 'PENDENTE',
      },
    });
    res.json(updatedEvent);
  } catch (error) {
    console.error("Update Event error:", error);
    res.status(500).json({ error: 'Erro ao atualizar evento.' });
  }
});

// DELETE: Apagar evento
app.delete('/api/events/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.eventoCalendarioDetalhado.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    console.error("Delete Event error:", error);
    res.status(500).json({ error: 'Erro ao deletar evento.' });
  }
});

// Restore Backup (Opcional, mantido para compatibilidade)
app.post('/api/events/restore', authenticateToken, async (req, res) => {
  const { events } = req.body;
  if (!Array.isArray(events)) {
    return res.status(400).json({ error: 'Formato inválido.' });
  }
  try {
    await prisma.$transaction(async (tx) => {
      await tx.eventoCalendarioDetalhado.deleteMany({});
      // Limpa os dados antes de restaurar
      const dataToCreate = events.map(({ id, date, ...rest }) => ({
          ...rest,
          start: rest.start || date // Garante que tenha start
      }));
      
      if (dataToCreate.length > 0) {
        await tx.eventoCalendarioDetalhado.createMany({ data: dataToCreate });
      }
    });
    res.status(200).json({ message: 'Backup restaurado.' });
  } catch (error) {
    console.error("Restore error:", error);
    res.status(500).json({ error: 'Erro ao restaurar backup.' });
  }
});

// --- CONTROLE DE MATERIAIS (principal) ---
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

// --- ROTA ANTIGA (full replace) — continua existindo para compatibilidade ---
app.put('/api/editais/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { nome, itens, saidas, empenhos } = req.body; // Remova 'municipioId' do req.body se ele estiver sendo enviado

  try {
    const result = await prisma.$transaction(async (tx) => {
      await tx.estoqueItem.deleteMany({ where: { editalId: id } });
      await tx.saidaItem.deleteMany({ where: { editalId: id } });
      await tx.empenho.deleteMany({ where: { editalId: id } });

      const updatedEdital = await tx.edital.update({
        where: { id },
        data: {
          nome,
          // 🔑 CORREÇÃO: Remove 'id' e 'editalId' de cada item/saída/empenho antes de criar
          itens: { create: (itens || []).map(({ id, editalId, ...item }) => item) },
          saidas: { create: (saidas || []).map(({ id, editalId, ...saida }) => saida) },
          empenhos: { create: (empenhos || []).map(({ id, editalId, ...emp }) => emp) },
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

// 🔴 🔴 🔴 NOVAS ROTAS INCREMENTAIS (itens / saídas / empenhos) 🔴 🔴 🔴

// 1) Atualizar SOMENTE itens do edital
app.put('/api/editais/:id/itens', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { itens } = req.body;

  if (!Array.isArray(itens)) {
    return res.status(400).json({ error: 'Corpo inválido: esperado { itens: [...] }' });
  }

  try {
    const itensParaCriar = (itens || []).map((it, idx) => {
      const quantidade = Number(it.quantidade) || 0;
      const valorUnitario = Number(it.valorUnitario) || 0;
      const valorTotal = Number(it.valorTotal) || (quantidade * valorUnitario);

      return {
        descricao: it.descricao || `Item ${idx + 1}`,
        marca: it.marca || null,
        unidade: it.unidade || 'un',
        quantidade,
        valorUnitario,
        valorTotal,
        editalId: id,
      };
    });

    await prisma.$transaction(async (tx) => {
      // apaga só os itens desse edital
      await tx.estoqueItem.deleteMany({ where: { editalId: id } });
      // recria
      if (itensParaCriar.length > 0) {
        await tx.estoqueItem.createMany({
          data: itensParaCriar,
        });
      }
    });

    const editalAtualizado = await prisma.edital.findUnique({
      where: { id },
      include: {
        itens: true,
        saidas: true,
        empenhos: true,
      },
    });

    res.json(editalAtualizado);
  } catch (error) {
    console.error('Update edital itens error:', error);
    res.status(500).json({ error: 'Erro ao atualizar itens do edital.' });
  }
});

// 2) Atualizar SOMENTE saídas do edital
app.put('/api/editais/:id/saidas', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { saidas } = req.body;

  if (!Array.isArray(saidas)) {
    return res.status(400).json({ error: 'Corpo inválido: esperado { saidas: [...] }' });
  }

  try {
    const saidasParaCriar = (saidas || []).map((s, idx) => {
      const quantidade = Number(s.quantidade) || 0;
      const valorUnitario = Number(s.valorUnitario) || 0;
      const valorTotal = Number(s.valorTotal) || (quantidade * valorUnitario);
      return {
        itemIndex: typeof s.itemIndex === 'number' ? s.itemIndex : Number(s.itemIndex) || 0,
        descricao: s.descricao || `Saída ${idx + 1}`,
        marca: s.marca || null,
        quantidade,
        valorUnitario,
        valorTotal,
        data: s.data || '',
        notaFiscal: s.notaFiscal || '',
        editalId: id,
      };
    });

    await prisma.$transaction(async (tx) => {
      await tx.saidaItem.deleteMany({ where: { editalId: id } });
      if (saidasParaCriar.length > 0) {
        await tx.saidaItem.createMany({
          data: saidasParaCriar,
        });
      }
    });

    const editalAtualizado = await prisma.edital.findUnique({
      where: { id },
      include: {
        itens: true,
        saidas: true,
        empenhos: true,
      },
    });

    res.json(editalAtualizado);
  } catch (error) {
    console.error('Update edital saidas error:', error);
    res.status(500).json({ error: 'Erro ao atualizar saídas do edital.' });
  }
});

// 3) Atualizar SOMENTE empenhos do edital
app.put('/api/editais/:id/empenhos', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { empenhos } = req.body;

  if (!Array.isArray(empenhos)) {
    return res.status(400).json({ error: 'Corpo inválido: esperado { empenhos: [...] }' });
  }

  try {
    const empenhosParaCriar = (empenhos || []).map((e, idx) => ({
      dataPedido: e.dataPedido || '',
      numeroPedido: e.numeroPedido || '',
      numeroProcesso: e.numeroProcesso || '',
      dataNotaFiscal: e.dataNotaFiscal || null,
      valorNotaFiscal: e.valorNotaFiscal != null ? Number(e.valorNotaFiscal) : null,
      empenhoPDF: e.empenhoPDF || null,
      notaFiscalPDF: e.notaFiscalPDF || null,
      statusPagamento: e.statusPagamento || 'PENDENTE', // Novo Campo Mapeado
      dataPagamento: e.dataPagamento || null,            // Novo Campo Mapeado
      editalId: id,
    }));

    await prisma.$transaction(async (tx) => {
      await tx.empenho.deleteMany({ where: { editalId: id } });
      if (empenhosParaCriar.length > 0) {
        await tx.empenho.createMany({
          data: empenhosParaCriar,
        });
      }
    });

    const editalAtualizado = await prisma.edital.findUnique({
      where: { id },
      include: {
        itens: true,
        saidas: true,
        empenhos: true,
      },
    });

    res.json(editalAtualizado);
  } catch (error) {
    console.error('Update edital empenhos error:', error);
    res.status(500).json({ error: 'Erro ao atualizar empenhos do edital.' });
  }
});

// --- RESTORE COMPLETO DE MATERIAIS ---
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

// --- MUNICÍPIOS / EDITAIS CRUD SIMPLES ---
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
    res.status(200).json({ message: 'Backup restaurado.' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao restaurar.' });
  }
});

// --- SIMULAÇÕES / COTAÇÕES / CALCULADORA (Simplificados) ---
app.get('/api/simulacoes', authenticateToken, async (req, res) => {
  const d = await prisma.simulacaoSalva.findMany({ include: { itens: true } });
  res.json(d);
});
app.post('/api/simulacoes', authenticateToken, async (req, res) => {
  const { id, itens, ...data } = req.body;
  const n = await prisma.simulacaoSalva.create({
    data: { ...data, itens: { create: itens } }, include: { itens: true }
  });
  res.status(201).json(n);
});
app.delete('/api/simulacoes/:id', authenticateToken, async (req, res) => {
  await prisma.simulacaoSalva.delete({ where: { id: req.params.id } });
  res.status(204).send();
});

app.get('/api/cotacoes', authenticateToken, async (req, res) => {
  const c = await prisma.cotacao.findMany({ include: { itens: true }, orderBy: { data: 'desc' } });
  res.json(c);
});
app.post('/api/cotacoes/import', authenticateToken, async (req, res) => {
  const { cotacoes } = req.body;
  await prisma.$transaction(
    cotacoes.map(c => prisma.cotacao.create({
      data: { local: c.local, data: c.data, itens: { create: c.itens } }
    }))
  );
  res.status(201).json({ msg: 'Importado' });
});
app.delete('/api/cotacoes/:id', authenticateToken, async (req, res) => {
  await prisma.cotacao.delete({ where: { id: req.params.id } });
  res.status(204).send();
});

app.get('/api/simulacoes-cotacoes', authenticateToken, async (req, res) => {
  const s = await prisma.simulacaoCotacaoSalva.findMany({ include: { itens: true } });
  res.json(s);
});
app.post('/api/simulacoes-cotacoes', authenticateToken, async (req, res) => {
  const { nome, data, itens } = req.body;
  const n = await prisma.simulacaoCotacaoSalva.create({
    data: { 
      nome, data, 
      itens: { create: itens.map(i => ({ 
        produto: i.produto, unidade: i.unidade, quantidade: i.quantidade, 
        valorUnitario: i.valorUnitario, valorTotal: i.valorTotal, marca: i.marca,
        origemCotacaoId: i.cotacaoOrigem.id, origemCotacaoLocal: i.cotacaoOrigem.local,
        origemCotacaoData: i.cotacaoOrigem.data
      })) } 
    }, include: { itens: true }
  });
  res.status(201).json(n);
});
app.delete('/api/simulacoes-cotacoes/:id', authenticateToken, async (req, res) => {
  await prisma.simulacaoCotacaoSalva.delete({ where: { id: req.params.id } });
  res.status(204).send();
});

app.get('/api/calculadora', authenticateToken, async (req, res) => {
  const c = await prisma.calculadoraSalva.findMany({ orderBy: { data: 'desc' } });
  res.json(c);
});
app.post('/api/calculadora', authenticateToken, async (req, res) => {
  const { nome, custos } = req.body;
  const n = await prisma.calculadoraSalva.create({ data: { nome, custos } });
  res.status(201).json(n);
});
app.delete('/api/calculadora/:id', authenticateToken, async (req, res) => {
  await prisma.calculadoraSalva.delete({ where: { id: req.params.id } });
  res.status(204).send();
});

// ==========================================
// --- NFe: EMISSORES (EMITENTES) ---
// ==========================================

app.get('/api/issuers', authenticateToken, async (req, res) => {
  try {
    const issuers = await prisma.nfeEmitente.findMany();
    res.json(issuers);
  } catch (error) {
    console.error("Erro buscar emissores:", error);
    res.status(500).json([]); 
  }
});

app.post('/api/issuers', authenticateToken, async (req, res) => {
  try {
    const data = req.body;
    if (!data.id) delete data.id;

    const newIssuer = await prisma.nfeEmitente.create({
      data: {
        cnpj: data.cnpj,
        razaoSocial: data.razaoSocial,
        inscricaoEstadual: data.inscricaoEstadual,
        email: data.email,
        crt: data.crt,
        endereco: data.endereco,
      }
    });
    res.json(newIssuer);
  } catch (error) {
    console.error("Erro ao criar emissor:", error);
    res.status(500).json({ error: 'Erro ao salvar emissor.' });
  }
});

app.put('/api/issuers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { id: _, ...data } = req.body;

    const updated = await prisma.nfeEmitente.update({
      where: { id },
      data: {
        cnpj: data.cnpj,
        razaoSocial: data.razaoSocial,
        inscricaoEstadual: data.inscricaoEstadual,
        email: data.email,
        crt: data.crt,
        endereco: data.endereco,
      }
    });
    res.json(updated);
  } catch (error) {
    console.error("Erro ao atualizar emissor:", error);
    res.status(500).json({ error: 'Erro ao atualizar emissor.' });
  }
});

app.delete('/api/issuers/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.nfeEmitente.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir.' });
  }
});

// ==========================================
// --- NFe: DESTINATÁRIOS (RECIPIENTS) ---
// ==========================================

app.get('/api/recipients', authenticateToken, async (req, res) => {
  try {
    const dest = await prisma.nfeDestinatario.findMany({ orderBy: { razaoSocial: 'asc' } });
    res.json(dest);
  } catch (error) {
    console.error(error);
    res.json([]); 
  }
});

app.post('/api/recipients', authenticateToken, async (req, res) => {
  const { id, ...data } = req.body;
  try {
    if (id) {
        const updated = await prisma.nfeDestinatario.upsert({ 
            where: { id },
            update: data,
            create: { ...data, id }
        });
        return res.json(updated);
    }
    const created = await prisma.nfeDestinatario.create({ data });
    res.status(201).json(created);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao salvar destinatário.' });
  }
});

app.delete('/api/recipients/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.nfeDestinatario.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir destinatário.' });
  }
});

// ==========================================
// --- NFe: PRODUTOS ---
// ==========================================

app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const prods = await prisma.nfeProduto.findMany({ orderBy: { descricao: 'asc' } });
    res.json(prods);
  } catch (error) {
    res.json([]);
  }
});

app.post('/api/products', authenticateToken, async (req, res) => {
  const { id, ...data } = req.body;
  try {
    if (id) {
        const updated = await prisma.nfeProduto.upsert({
            where: { id },
            update: data,
            create: { ...data, id }
        });
        return res.json(updated);
    }
    const created = await prisma.nfeProduto.create({ data });
    res.status(201).json(created);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao salvar produto.' });
  }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.nfeProduto.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir produto.' });
  }
});

// ==========================================
// --- NFe: NOTAS FISCAIS (CORRIGIDA E INTELIGENTE) ---
// ==========================================

app.get('/api/nfe/notas', authenticateToken, async (req, res) => {
  try {
    // Ordena por Data de Emissão (mais recente primeiro)
    const notas = await prisma.nfeDocumento.findMany({ orderBy: { dataEmissao: 'desc' } });
    const mappedNotas = notas.map(n => {
        const base = n.fullData || {};
        return {
            ...base, 
            id: n.id,
            status: n.status,
            chaveAcesso: n.chaveAcesso,
            xmlAssinado: n.xmlAssinado,
            dataEmissao: n.dataEmissao ? new Date(n.dataEmissao).toISOString() : base.dataEmissao
        };
    });
    res.json(mappedNotas);
  } catch (error) {
    console.error(error);
    res.json([]);
  }
});

// POST: Salvar Nota (Com Auto-Cadastro e ATUALIZAÇÃO INTELIGENTE via Chave)
app.post('/api/nfe/notas', authenticateToken, async (req, res) => {
  const invoiceData = req.body;
  try {
    // --- 1. LÓGICA DE AUTO-CADASTRO DE DESTINATÁRIO ---
    if (invoiceData.destinatario && invoiceData.destinatario.cnpj) {
        try {
            const existingDest = await prisma.nfeDestinatario.findFirst({
                where: { cnpj: invoiceData.destinatario.cnpj }
            });
            if (!existingDest) {
                await prisma.nfeDestinatario.create({
                    data: {
                        cnpj: invoiceData.destinatario.cnpj,
                        razaoSocial: invoiceData.destinatario.razaoSocial,
                        inscricaoEstadual: invoiceData.destinatario.inscricaoEstadual || '',
                        endereco: invoiceData.destinatario.endereco || {},
                        email: invoiceData.destinatario.email || ''
                    }
                });
            }
        } catch (e) { console.error("Auto-cadastro dest falhou (ignorado):", e); }
    }

    // --- 2. LÓGICA DE AUTO-CADASTRO DE PRODUTOS (CORRIGIDO com Promise.all) ---
    if (invoiceData.produtos && Array.isArray(invoiceData.produtos)) {
        await Promise.all(invoiceData.produtos.map(async (prod) => {
            try {
                 const existingProd = await prisma.nfeProduto.findFirst({
                    where: { codigo: prod.codigo }
                 });
                 if (!existingProd) {
                    await prisma.nfeProduto.create({
                        data: {
                            codigo: prod.codigo,
                            descricao: prod.descricao,
                            ncm: prod.ncm || '',
                            cfop: prod.cfop || '',
                            unidade: prod.unidade,
                            valorUnitario: parseFloat(prod.valorUnitario) || 0,
                            gtin: prod.gtin || 'SEM GTIN',
                            tax: prod.tax || {}
                        }
                    });
                 }
            } catch (e) { console.error("Auto-cadastro prod falhou (ignorado):", e); }
        }));
    }

    // --- 3. PREPARAÇÃO E SALVAMENTO DA NOTA ---
    const dataToSave = {
        numero: invoiceData.numero,
        serie: invoiceData.serie,
        chaveAcesso: invoiceData.chaveAcesso,
        status: invoiceData.status || 'draft',
        xmlAssinado: invoiceData.xmlAssinado,
        dataEmissao: new Date(invoiceData.dataEmissao),
        emitenteCnpj: invoiceData.emitente?.cnpj,
        fullData: invoiceData 
    };

    let existingRecord = null;

    // A. Se veio ID explícito (edição manual no sistema)
    if (invoiceData.id) {
        existingRecord = await prisma.nfeDocumento.findUnique({ where: { id: invoiceData.id } });
    } 
    // B. Se não tem ID, mas tem Chave de Acesso (Importação de XML)
    else if (invoiceData.chaveAcesso) {
        existingRecord = await prisma.nfeDocumento.findFirst({ 
            where: { chaveAcesso: invoiceData.chaveAcesso } 
        });
    }

    if (existingRecord) {
        // ATUALIZA (UPDATE)
        const updated = await prisma.nfeDocumento.update({
            where: { id: existingRecord.id },
            data: dataToSave
        });
        return res.json({ ...invoiceData, id: updated.id });
    } else {
        // CRIA (CREATE)
        const created = await prisma.nfeDocumento.create({
            data: { ...dataToSave, id: invoiceData.id }
        });
        res.status(201).json({ ...invoiceData, id: created.id });
    }

  } catch (error) {
    console.error("Erro fatal na rota POST /api/nfe/notas:", error);
    res.status(500).json({ error: 'Erro ao salvar nota fiscal.' });
  }
});

app.delete('/api/nfe/notas/:id', authenticateToken, async (req, res) => {
  try {
    await prisma.nfeDocumento.delete({ where: { id: req.params.id } });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro ao excluir nota fiscal.' });
  }
});

app.post('/api/nfe/transmitir', authenticateToken, async (req, res) => {
    try {
        const { id } = req.body;
        
        // 1. Busca a Nota e o Emitente Completo
        const nfeDoc = await prisma.nfeDocumento.findUnique({ 
            where: { id },
            include: { emitente: true } // Precisamos buscar o cadastro da empresa
        });

        if (!nfeDoc) return res.status(404).json({ error: 'Nota não encontrada' });

        // 2. Busca o Certificado no Banco de Dados (NÃO NO DISCO)
        // Supondo que você salvou o certificado na tabela 'Issuer' ou na própria 'Entity'
        // Ajuste 'certificadoArquivo' para o nome do campo no seu banco
        const issuer = await prisma.issuer.findUnique({
            where: { cnpj: nfeDoc.emitente.cnpj }
        });

        if (!issuer || !issuer.certificadoArquivo || !issuer.certificadoSenha) {
            return res.status(400).json({ error: 'Certificado digital não cadastrado para este emitente.' });
        }

        // Se estiver salvo como Base64 no banco, converte para Buffer
        // Se já estiver como Bytes no Prisma, use direto
        const pfxBuffer = Buffer.isBuffer(issuer.certificadoArquivo) 
            ? issuer.certificadoArquivo 
            : Buffer.from(issuer.certificadoArquivo, 'base64');

        // 3. Instancia o Serviço passando o BUFFER e a SENHA
        const service = new NFeService(pfxBuffer, issuer.certificadoSenha);
        const xml = service.generateXML(nfeDoc.fullData);
        const xmlAssinado = service.signXML(xml);
        console.log("Transmitindo NFe para SEFAZ...");
        const retornoSefaz = await service.transmit(xmlAssinado); // Retorno é o XML bruto da SEFAZ

// 4. Processamento da Resposta da SEFAZ (cStat)
        const result = await parseXml(retornoSefaz, { explicitArray: false });

        // A estrutura do XML de resposta (SOAP) é complexa. O caminho abaixo é o padrão:
        const nfeAutorizacaoResult = result['soap12:Envelope']['soap12:Body']['nfeAutorizacaoLoteResult']['retEnviNFe'];
        const protNFe = nfeAutorizacaoResult?.protNFe;

        const cStat = nfeAutorizacaoResult?.cStat || (protNFe ? protNFe.infProt.cStat : null);
        const xMotivo = nfeAutorizacaoResult?.xMotivo || (protNFe ? protNFe.infProt.xMotivo : "Erro desconhecido");
        const protocolo = protNFe ? protNFe.infProt.nProt : null;

        let newStatus = 'error';
        let responseJson = {};

        if (cStat === '100') {
            newStatus = 'authorized';
            console.log(`NFe Autorizada! Protocolo: ${protocolo}`);
            
            // Salva o protocolo e status de sucesso
            await prisma.nfeDocumento.update({
                where: { id },
                data: { 
                    status: newStatus, 
                    xmlAssinado: xmlAssinado,
                    protocoloAutorizacao: protocolo // Campo necessário no seu Schema Prisma!
                }
            });
            responseJson = { sucesso: true, xml: xmlAssinado, status: newStatus, protocolo: protocolo };
            res.json(responseJson);

        } else if (cStat === '103') {
            // Lote em processamento - precisa de consulta posterior (Simplificação: salva como pending)
            newStatus = 'processing';
            console.warn(`Lote em Processamento. Motivo: ${xMotivo}`);
            await prisma.nfeDocumento.update({
                where: { id },
                data: { status: newStatus }
            });
            responseJson = { sucesso: true, status: newStatus, erro: xMotivo };
            res.json(responseJson);
            
        } else {
            // Rejeição ou outro erro (2xx, 3xx, 4xx, etc.)
            newStatus = 'rejected';
            console.error(`Rejeição NFe: [${cStat}] ${xMotivo}`);
            
            // Salva o status de rejeição
            await prisma.nfeDocumento.update({
                where: { id },
                data: { status: newStatus }
            });
            
            responseJson = { sucesso: false, status: newStatus, erro: `Rejeição [${cStat || '??'}]: ${xMotivo}` };
            res.status(400).json(responseJson); // Retorna 400 Bad Request para o Frontend
        }

    } catch (error) {
        console.error("Erro Crítico na Transmissão:", error);
        res.status(500).json({ sucesso: false, erro: `Erro de Servidor: ${error.message}` });
    }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
