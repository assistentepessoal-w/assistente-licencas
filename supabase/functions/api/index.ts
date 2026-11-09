// SERVIDOR DE LICENÇAS DO ASSISTENTE DENTRO DO SUPABASE (08/11/2026).
//
// Pedido dele: o site de licenças na conta assistentepessoal-w, "pelo GitHub". O GitHub Pages só serve página parada,
// e a conta não tem Vercel; então a parte que confere e ASSINA as licenças virou esta Edge Function, no mesmo
// projeto Supabase das tabelas (sql/001_assistente.sql), e o painel (index.html) mora no GitHub Pages.
//
// É o api/_nucleo.py do Vercel, linha por linha: as mesmas rotas (/api/conferir, /api/teste, /api/versao, /api/admin),
// as mesmas respostas e a MESMA assinatura Ed25519 (corpo JSON em base64url + "." + assinatura em base64url). O
// programa (core/licenca.py) confere com a chave pública que já tem embutida: nada muda para ele além do endereço.
//
// NINGUÉM COLA SEGREDO (09/11/2026): a chave de assinatura é criada pelo próprio servidor na primeira vez e guardada
// na tabela config_segura (sql/002, só a service_role lê); a parte PÚBLICA sai em /api/chave-publica e vai embutida
// no ASSISTENTE 2.7.0 (os da 2.6.0 seguem no servidor antigo, com a chave antiga). A senha do painel é criada pelo
// dono no primeiro acesso e fica só em hash PBKDF2. Se existirem os segredos LICENCA_CHAVE_PRIVADA /
// LICENCA_ADMIN_SENHA na função, eles valem no lugar. SUPABASE_URL e a chave de serviço o Supabase entrega sozinho.
// A função roda com "Verify JWT" ligado: o programa e o painel mandam a chave PÚBLICA (anon) do projeto.

const FOLGA_DIAS = 7;
const TESTE_MINUTOS = 15;
const PLANOS = ["mensal", "vitalicia"];
const PRODUTO = "assistente";
const PREFIXO = "ASST";
const VERSAO_OK = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const SHA256_OK = /^[0-9a-f]{64}$/;

class ErroDoPedido extends Error {}

// Chave, URL e chave privada são ASCII: tira o que vier junto ao colar (BOM, quebra de linha, espaço invisível).
const limpo = (v: unknown) => [...String(v ?? "")].filter((c) => {
  const o = c.charCodeAt(0);
  return o > 32 && o < 127;
}).join("");

const agora = () => new Date();
const iso = (d: Date | null) => (d ? d.toISOString().replace(/\.\d{3}Z$/, "Z") : null);
const deIso = (s: unknown) => (s ? new Date(String(s)) : null);
const seg = (d: Date) => Math.floor(d.getTime() / 1000);
const dias = (d: Date, n: number) => new Date(d.getTime() + n * 86400000);
const inteiro = (v: unknown, padrao = 0) => {
  if (v === undefined || v === null || v === "") return padrao;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new ErroDoPedido(`número inválido: ${v}`);
  return Math.trunc(n);
};

function novaChave() {
  // ASST-XXXX-XXXX-XXXX-XXXX, sem letras que confundem (0/O, 1/I). 32 letras: o byte % 32 não vicia.
  const letras = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = crypto.getRandomValues(new Uint8Array(16));
  const grupos = [0, 4, 8, 12].map((i) => [...b.slice(i, i + 4)].map((x) => letras[x % 32]).join(""));
  return PREFIXO + "-" + grupos.join("-");
}

function normalizaChave(c: unknown) {
  let s = [...String(c ?? "").toUpperCase()].filter((ch) => /[A-Z0-9]/.test(ch)).join("");
  if (s.startsWith(PREFIXO)) s = s.slice(PREFIXO.length);
  return s.length === 16 ? PREFIXO + "-" + [0, 4, 8, 12].map((i) => s.slice(i, i + 4)).join("-") : "";
}

// ---------------------------------------------------------------------------
// Assinatura (Ed25519, a mesma chave do servidor antigo)
// ---------------------------------------------------------------------------
let chavePrivada: CryptoKey | null = null;
let chavePublica = "";          // base64 dos 32 bytes (o formato da CHAVE_PUBLICA do core/licenca.py)

function b64(b: Uint8Array) {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
const deB64 = (s: string) => Uint8Array.from(atob(limpo(s)), (c) => c.charCodeAt(0));
const b64u = (b: Uint8Array) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// config_segura: o que o servidor cria e guarda sozinho (sql/002_config_segura.sql)
async function lerConfig(nome: string): Promise<string> {
  const r = await banco("GET", `config_segura?nome=eq.${encodeURIComponent(nome)}&select=valor`);
  return r && r.length ? String(r[0].valor || "") : "";
}
async function criarConfig(nome: string, valor: string) {
  // dois pedidos juntos: o segundo bate na chave primária e vale o que o primeiro gravou
  try { await banco("POST", "config_segura", { nome, valor }, "return=minimal"); return true; } catch { return false; }
}

async function chaveDeAssinar() {
  if (chavePrivada) return chavePrivada;
  const daVariavel = limpo(Deno.env.get("LICENCA_CHAVE_PRIVADA"));
  if (daVariavel) {
    const semente = deB64(daVariavel);
    if (semente.length !== 32) throw new Error("LICENCA_CHAVE_PRIVADA inválida");
    // PKCS#8 de Ed25519 = cabeçalho fixo + os 32 bytes da semente
    const cab = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    chavePrivada = await crypto.subtle.importKey("pkcs8", new Uint8Array([...cab, ...semente]), { name: "Ed25519" },
      false, ["sign"]);
    return chavePrivada;
  }
  // A chave do próprio servidor: privada e pública numa linha só (as duas sempre do mesmo par)
  let guardada = await lerConfig("assinatura");
  if (!guardada) {
    const par = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", par.privateKey));
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", par.publicKey));
    await criarConfig("assinatura", JSON.stringify({ pkcs8: b64(pkcs8), publica: b64(pub) }));
    guardada = await lerConfig("assinatura");
  }
  const j = JSON.parse(guardada);
  chavePublica = j.publica;
  chavePrivada = await crypto.subtle.importKey("pkcs8", deB64(j.pkcs8), { name: "Ed25519" }, false, ["sign"]);
  return chavePrivada;
}

async function publicaDoServidor() {
  if (limpo(Deno.env.get("LICENCA_CHAVE_PRIVADA"))) return "";   // a chave antiga: a pública já está no programa
  await chaveDeAssinar();
  return chavePublica;
}

// json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False), como no servidor antigo
function jsonOrdenado(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jsonOrdenado).join(",") + "]";
  const o = v as Record<string, unknown>;
  return "{" + Object.keys(o).sort().filter((k) => o[k] !== undefined)
    .map((k) => JSON.stringify(k) + ":" + jsonOrdenado(o[k])).join(",") + "}";
}

async function assinar(dados: Record<string, unknown>) {
  const corpo = new TextEncoder().encode(jsonOrdenado(dados));
  const assinatura = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, await chaveDeAssinar(), corpo));
  return b64u(corpo) + "." + b64u(assinatura);
}

// ---------------------------------------------------------------------------
// Onde as licenças moram (as tabelas, pelo PostgREST do próprio projeto)
// ---------------------------------------------------------------------------
function chaveDoBanco() {
  const antiga = limpo(Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));
  if (antiga) return antiga;
  try {   // projetos só com as chaves novas: {"default": "sb_secret_..."}
    const j = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") || "{}");
    const v = Object.values(j)[0];
    if (v) return limpo(v);
  } catch { /* sem chave nova */ }
  return "";
}

async function banco(metodo: string, caminho: string, corpo?: unknown, prefer = "return=representation") {
  const chave = chaveDoBanco();
  const cab: Record<string, string> = { apikey: chave, "Content-Type": "application/json", Prefer: prefer };
  // a chave antiga (JWT "eyJ...") vai também no Authorization; a nova ("sb_secret_") só no apikey
  if (!chave.startsWith("sb_")) cab.Authorization = "Bearer " + chave;
  const base = limpo(Deno.env.get("SUPABASE_URL")).replace(/\/$/, "") + "/rest/v1/";
  const r = await fetch(base + caminho, {
    method: metodo, headers: cab, body: corpo === undefined ? undefined : JSON.stringify(corpo),
  });
  const txt = await r.text();
  if (!r.ok) throw new Error(`banco ${r.status}: ${txt.slice(0, 300)}`);
  return txt ? JSON.parse(txt) : [];
}

type Linha = Record<string, any>;
const um = (r: Linha[]) => (r && r.length ? r[0] : null);
const q = encodeURIComponent;

const B = {
  licenca: async (chave: string) => um(await banco("GET", `licencas?chave=eq.${q(chave)}&select=*`)),
  licencaId: async (id: number) => um(await banco("GET", `licencas?id=eq.${id}&select=*`)),
  licencas: () => banco("GET", "licencas?select=*&order=id.desc"),
  criarLicenca: async (d: Linha) => (await banco("POST", "licencas", d))[0],
  mudarLicenca: async (id: number, d: Linha) => um(await banco("PATCH", `licencas?id=eq.${id}`, d)),
  ativacoes: (lid?: number) =>
    banco("GET", `ativacoes?${lid !== undefined ? `licenca_id=eq.${lid}&` : ""}select=*&order=id.desc`),
  criarAtivacao: async (d: Linha) => (await banco("POST", "ativacoes", d))[0],
  mudarAtivacao: async (id: number, d: Linha) => um(await banco("PATCH", `ativacoes?id=eq.${id}`, d)),
  registrar: async (lid: number | null, texto: string) => {
    try {
      await banco("POST", "registros", { licenca_id: lid, texto: texto.slice(0, 500), em: iso(agora()) });
    } catch { /* o registro nunca derruba a resposta */ }
  },
  registros: (limite = 200) => banco("GET", `registros?select=*&order=id.desc&limit=${limite}`),
  versao: async () => um(await banco("GET", `versoes?produto=eq.${PRODUTO}&select=*`)),
  versoes: () => banco("GET", "versoes?select=*"),
  gravarVersao: async (d: Linha) =>
    (await banco("POST", "versoes?on_conflict=produto", d, "resolution=merge-duplicates,return=representation"))[0],
  teste: async (pc: string) => um(await banco("GET", `testes?pc_id=eq.${q(pc)}&select=*`)),
  criarTeste: async (d: Linha) => {
    // dois pedidos ao mesmo tempo do mesmo PC: o segundo bate na chave única e lê o primeiro
    try { return (await banco("POST", "testes", d))[0]; } catch { return await B.teste(d.pc_id); }
  },
  testes: (limite = 200) => banco("GET", `testes?select=*&order=id.desc&limit=${limite}`),
  apagarTeste: (id: number) => banco("DELETE", `testes?id=eq.${id}`, undefined, "return=minimal"),
};

// ---------------------------------------------------------------------------
// A conferência que o programa faz (ativa o PC na primeira vez)
// ---------------------------------------------------------------------------
async function conferir(chaveDada: unknown, pcDado: unknown, pcNome: string, versao: string, ativar: boolean):
  Promise<[number, Linha]> {
  const chave = normalizaChave(chaveDada);
  const pc = String(pcDado ?? "").slice(0, 128);
  if (!chave || pc.length < 16) return [400, { erro: "chave ou PC inválido" }];
  const lic = await B.licenca(chave);
  if (!lic) return [404, { erro: "chave não encontrada" }];
  const ag = agora();
  const ativas = (await B.ativacoes(lic.id)).filter((x: Linha) => !x.liberada);
  let minha = ativas.find((x: Linha) => x.pc_id === pc) || null;
  let motivo = "";
  let status = lic.status;
  const vence = deIso(lic.vence_em);
  if (status === "ativa" && lic.plano === "mensal" && vence && vence < ag) {
    status = "vencida"; motivo = "a mensalidade venceu";
  }
  if (status === "ativa" && !minha && !ativar) {
    status = "removida"; motivo = "este PC não está ativado nessa licença (ou foi liberado no painel)";
  }
  if (status === "ativa" && !minha) {
    if (ativas.length >= Number(lic.max_pcs || 1)) {
      return [409, { erro: `essa licença já está em ${ativas.length} PC(s), o máximo dela. ` +
        "Peça a troca de PC a quem vendeu." }];
    }
    minha = await B.criarAtivacao({ licenca_id: lic.id, pc_id: pc, pc_nome: String(pcNome).slice(0, 120),
      versao: String(versao).slice(0, 40), ativado_em: iso(ag), visto_em: iso(ag), liberada: false });
    await B.registrar(lic.id, `PC ativado: ${pcNome || pc.slice(0, 12)}`);
  } else if (minha) {
    await B.mudarAtivacao(minha.id, { visto_em: iso(ag), versao: String(versao).slice(0, 40),
      pc_nome: String(pcNome).slice(0, 120) || minha.pc_nome });
  }
  const motivoFinal = motivo || ({ pausada: "a licença está pausada", cancelada: "a licença foi cancelada" } as
    Record<string, string>)[status] || "";
  const dados = { tipo: "licenca", chave, pc, plano: lic.plano, status, motivo: motivoFinal,
    cliente: lic.cliente || "", vence: lic.plano === "mensal" ? iso(vence) : null,
    max_pcs: Number(lic.max_pcs || 1), emitida: seg(ag), produto: PRODUTO, folga_ate: seg(dias(ag, FOLGA_DIAS)) };
  return [200, { licenca: await assinar(dados), status, motivo: motivoFinal }];
}

// ---------------------------------------------------------------------------
// O teste de 15 minutos (uma vez por PC)
// ---------------------------------------------------------------------------
async function teste(pcDado: unknown, pcNome: string, versao: string): Promise<[number, Linha]> {
  const pc = String(pcDado ?? "").slice(0, 128);
  if (pc.length < 16) return [400, { erro: "PC inválido" }];
  const ag = agora();
  let t = await B.teste(pc);
  if (!t) {
    t = await B.criarTeste({ pc_id: pc, pc_nome: String(pcNome).slice(0, 120), versao: String(versao).slice(0, 40),
      comecou_em: iso(ag) });
    await B.registrar(null, `Teste de ${TESTE_MINUTOS} minutos começou: ${pcNome || pc.slice(0, 12)}`);
  }
  const comecou = deIso(t.comecou_em)!;
  const termina = new Date(comecou.getTime() + TESTE_MINUTOS * 60000);
  const dados = { tipo: "teste", pc, produto: PRODUTO, comecou: seg(comecou), termina: seg(termina), emitida: seg(ag) };
  return [200, { teste: await assinar(dados), termina: iso(termina), acabou: ag >= termina }];
}

// ---------------------------------------------------------------------------
// O painel (só com a senha)
// ---------------------------------------------------------------------------
function iguais(a: Uint8Array, b: Uint8Array) {
  if (!a.length || a.length !== b.length) return false;
  let dif = 0;
  for (let i = 0; i < a.length; i++) dif |= a[i] ^ b[i];
  return dif === 0;
}

const senhaDoSegredo = () => (Deno.env.get("LICENCA_ADMIN_SENHA") || "").replace(/﻿/g, "").trim();
const limpaSenha = (s: unknown) => String(s ?? "").replace(/﻿/g, "").trim();

// PBKDF2-SHA256: "pbkdf2$<voltas>$<sal base64>$<hash base64>" — a senha em si nunca fica guardada
async function hashSenha(senha: string, sal: Uint8Array, voltas: number) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(senha), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: sal, iterations: voltas },
    base, 256));
}

async function senhaDefinida() {
  return Boolean(senhaDoSegredo() || await lerConfig("painel_senha"));
}

async function senhaOk(senha: unknown) {
  const dada = limpaSenha(senha);
  const doSegredo = senhaDoSegredo();
  if (doSegredo) return iguais(new TextEncoder().encode(dada), new TextEncoder().encode(doSegredo));
  const guardada = await lerConfig("painel_senha");
  const p = guardada.split("$");
  if (p.length !== 4 || p[0] !== "pbkdf2" || !dada) return false;
  return iguais(await hashSenha(dada, deB64(p[2]), Number(p[1])), deB64(p[3]));
}

// O primeiro acesso ao painel: o dono cria a senha (só enquanto não existe nenhuma).
async function criarSenha(nova: unknown): Promise<[number, Linha]> {
  const s = limpaSenha(nova);
  if (s.length < 8) return [400, { erro: "a senha precisa de pelo menos 8 caracteres" }];
  if (await senhaDefinida()) return [409, { erro: "a senha do painel já foi criada" }];
  const sal = crypto.getRandomValues(new Uint8Array(16));
  const voltas = 150000;
  const ok = await criarConfig("painel_senha", `pbkdf2$${voltas}$${b64(sal)}$${b64(await hashSenha(s, sal, voltas))}`);
  if (!ok) return [409, { erro: "a senha do painel já foi criada" }];
  await B.registrar(null, "Senha do painel criada");
  return [200, { ok: true }];
}

async function admin(acao: string, d: Linha): Promise<Linha> {
  if (acao === "listar") {
    const ativ = await B.ativacoes();
    const lics = await B.licencas();
    for (const x of lics) x.pcs = ativ.filter((a: Linha) => a.licenca_id === x.id);
    return { licencas: lics, registros: await B.registros(80), versoes: await B.versoes(),
      testes: await B.testes(100), teste_minutos: TESTE_MINUTOS };
  }
  if (acao === "criar") {
    const plano = d.plano;
    if (!PLANOS.includes(plano)) throw new ErroDoPedido("plano deve ser mensal ou vitalicia");
    const meses = Math.max(1, inteiro(d.meses, 1));
    const lic = await B.criarLicenca({
      chave: novaChave(), cliente: String(d.cliente || "").slice(0, 120), contato: String(d.contato || "").slice(0, 120),
      plano, max_pcs: Math.max(1, Math.min(100, inteiro(d.max_pcs, 1))), status: "ativa",
      vence_em: plano === "mensal" ? iso(dias(agora(), 30 * meses)) : null,
      obs: String(d.obs || "").slice(0, 500), criado_em: iso(agora()),
    });
    await B.registrar(lic.id, `Licença criada (${plano}, ${lic.max_pcs} PC) para ${lic.cliente || "-"}`);
    return { licenca: lic };
  }
  if (acao === "publicar_versao") {
    const versao = String(d.versao || "").trim();
    const url = String(d.url || "").trim();
    const sha = String(d.sha256 || "").trim().toLowerCase();
    if (!VERSAO_OK.test(versao)) throw new ErroDoPedido("versão no formato 2.6.0");
    if (!url.startsWith("https://") || url.length > 500) throw new ErroDoPedido("o link do instalador tem de ser https://");
    if (!SHA256_OK.test(sha)) throw new ErroDoPedido("SHA-256 do instalador: 64 letras e números");
    const v = await B.gravarVersao({ produto: PRODUTO, versao, url, sha256: sha,
      notas: String(d.notas || "").slice(0, 1000), publicado_em: iso(agora()) });
    await B.registrar(null, `Versão ${versao} publicada`);
    return { versao: v };
  }
  if (acao === "liberar_teste") {
    // o cliente pediu mais tempo para testar: apaga o teste daquele PC e ele ganha outros 15 minutos
    const tid = inteiro(d.teste_id, 0);
    await B.apagarTeste(tid);
    await B.registrar(null, `Teste liberado de novo (registro ${tid})`);
    return { ok: true };
  }
  const lid = inteiro(d.id, 0);
  let lic = await B.licencaId(lid);
  if (!lic) throw new ErroDoPedido("licença não encontrada");
  if (acao === "pausar" || acao === "cancelar" || acao === "reativar") {
    const novo = ({ pausar: "pausada", cancelar: "cancelada", reativar: "ativa" } as Record<string, string>)[acao];
    lic = await B.mudarLicenca(lid, { status: novo });
    await B.registrar(lid, `Licença ${novo}`);
    return { licenca: lic };
  }
  if (acao === "renovar") {
    if (lic.plano !== "mensal") throw new ErroDoPedido("só a mensal vence");
    const meses = Math.max(1, inteiro(d.meses, 1));
    const vence = deIso(lic.vence_em);
    const base = vence && vence > agora() ? vence : agora();
    lic = await B.mudarLicenca(lid, { vence_em: iso(dias(base, 30 * meses)),
      status: lic.status !== "cancelada" ? "ativa" : lic.status });
    await B.registrar(lid, `Renovada por ${meses} mês(es), até ${String(lic.vence_em).slice(0, 10)}`);
    return { licenca: lic };
  }
  if (acao === "editar") {
    const campos: Linha = {};
    if ("max_pcs" in d) campos.max_pcs = Math.max(1, Math.min(100, inteiro(d.max_pcs, 1)));
    for (const k of ["cliente", "contato", "obs"]) if (k in d) campos[k] = String(d[k] || "").slice(0, 500);
    if ("plano" in d && PLANOS.includes(d.plano)) {
      campos.plano = d.plano;
      if (d.plano === "vitalicia") campos.vence_em = null;
      else if (!lic.vence_em) campos.vence_em = iso(dias(agora(), 30));
    }
    if ("vence_em" in d && d.vence_em) {
      const s = String(d.vence_em);
      campos.vence_em = iso(new Date(s.includes("T") ? s : s + "T23:59:59Z"));
    }
    lic = await B.mudarLicenca(lid, campos);
    await B.registrar(lid, "Licença editada: " + Object.keys(campos).join(", "));
    return { licenca: lic };
  }
  if (acao === "liberar_pc") {
    const aid = inteiro(d.ativacao_id, 0);
    const a = (await B.ativacoes(lid)).find((x: Linha) => x.id === aid);
    if (!a) throw new ErroDoPedido("PC não encontrado nessa licença");
    await B.mudarAtivacao(aid, { liberada: true });
    await B.registrar(lid, `PC liberado para troca: ${a.pc_nome || String(a.pc_id).slice(0, 12)}`);
    return { ok: true };
  }
  throw new ErroDoPedido("ação desconhecida");
}

async function versaoPublicada(): Promise<[number, Linha]> {
  const v = await B.versao();
  if (!v) return [404, { erro: "nenhuma versão publicada" }];
  const dados = { tipo: "versao", produto: PRODUTO, versao: v.versao, url: v.url, sha256: v.sha256,
    notas: v.notas || "", publicado_em: v.publicado_em || "", emitida: seg(agora()) };
  return [200, { versao: await assinar(dados) }];
}

// ---------------------------------------------------------------------------
// As rotas: /functions/v1/api/<conferir|teste|versao|admin>
// ---------------------------------------------------------------------------
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function responder(codigo: number, corpo: Linha) {
  return new Response(JSON.stringify(corpo), {
    status: codigo,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  const rota = new URL(req.url).pathname.split("/").filter(Boolean).pop() || "";
  try {
    if (rota === "versao" && req.method === "GET") return responder(...(await versaoPublicada()));
    // a parte PÚBLICA da chave de assinatura (vai embutida no programa)
    if (rota === "chave-publica" && req.method === "GET") {
      return responder(200, { chave_publica: await publicaDoServidor() });
    }
    if (req.method !== "POST") return responder(404, { erro: "rota desconhecida" });
    const bruto = await req.text();
    if (rota !== "admin" && bruto.length > 4000) return responder(413, { erro: "pedido grande demais" });
    const d = JSON.parse(bruto || "{}");
    if (rota === "conferir") {
      return responder(...(await conferir(d.chave, d.pc_id, d.pc_nome || "", d.versao || "", !!d.ativar)));
    }
    if (rota === "teste") return responder(...(await teste(d.pc_id, d.pc_nome || "", d.versao || "")));
    if (rota === "admin") {
      // sem senha: só saber se ela já existe e criá-la no primeiro acesso
      if (d.acao === "estado_painel") return responder(200, { senha_definida: await senhaDefinida() });
      if (d.acao === "criar_senha") return responder(...(await criarSenha(d.nova)));
      if (!(await senhaOk(d.senha))) {
        await new Promise((r) => setTimeout(r, 1500));   // tentativa de senha custa tempo
        return responder(401, { erro: "senha errada" });
      }
      try {
        return responder(200, await admin(String(d.acao || ""), d));
      } catch (e) {
        if (e instanceof ErroDoPedido) return responder(400, { erro: e.message });
        throw e;
      }
    }
    return responder(404, { erro: "rota desconhecida" });
  } catch (e) {
    const err = e as Error;
    return responder(500, {
      erro: rota === "admin" ? `${err.name}: ${String(err.message).slice(0, 200)}`
        : `servidor de licenças com problema: ${err.name}`,
    });
  }
});
