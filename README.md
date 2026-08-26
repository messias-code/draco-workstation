# 🐉 Draco-Workstation

Ferramenta de **auditoria de redes** que examina um computador, descobre por onde
ele "fala com o mundo", identifica falhas de segurança conhecidas e escreve um
**relatório claro** — tudo com **um único comando**.

É um *check-up de saúde* de um alvo na rede: descobre portas, identifica serviços
e versões, correlaciona CVEs e entrega um laudo pronto para o profissional
**defender** (saber o que corrigir) ou, em teste autorizado, **atacar de forma
ética**. O Draco apenas observa e cataloga — **não** invade nem explora nada.

> 📘 **Guia visual para iniciantes** (com o relatório real explicado passo a passo):
> este README cobre o mesmo conteúdo em texto.

---

## 🚀 Início rápido

```bash
draco                      # alvo padrão de testes (scanme.nmap.org)
draco scanme.nmap.org      # um site/domínio
draco 45.33.32.156         # um endereço IP
draco -f targets.txt       # vários alvos (um por linha)
```

É só isso. O motor não expõe configurações complicadas. Ele inteligentemente descobre o host, varre as portas, identifica serviços e
versões, correlaciona CVEs e **gera o relatório sozinho**. O laudo sai em
`outputs/relatorio_draco_<IP>_<DATA>.md`.

> 🔑 **Root é obrigatório.** A varredura sênior (SYN furtivo, masscan, OS
> fingerprint, evasão) depende de *raw sockets*. O comando `draco` **se eleva
> sozinho** e pede a senha do seu computador **uma vez**. Sem root, ele não roda.

---

## 🔐 Inteligência Artificial e Bancos de Vulnerabilidades (.env)

O Draco usa bases locais (offline) por padrão, mas é **altamente recomendado** integrá-lo com APIs do governo americano (NVD) e bases privadas (Vulners) para ter relatórios ricos.

Nós usamos um arquivo simples e invisível chamado `.env` na raiz do projeto para isso. Copie o arquivo `.env.example` para `.env` e preencha as chaves:

### Como obter a chave do NVD (NIST):
O NVD aumentará drasticamente o limite de consultas de vulnerabilidades (CVEs).
1. Acesse: https://nvd.nist.gov/developers/request-an-api-key
2. Preencha o formulário rápido com o seu e-mail.
3. Eles enviarão a chave (um longo código) na sua caixa de entrada (olhe o Spam).
4. Cole no seu `.env` na linha: `NVD_API_KEY=`

### Como obter a chave do Vulners:
O Vulners enriquece o relatório encontrando *exploits* públicos super atualizados.
1. Acesse: https://vulners.com/
2. Faça Login (Google/GitHub ou cadastre-se).
3. No canto superior direito, vá no seu perfil > aba **API Keys**.
4. Crie uma chave de escopo **api**, licença **Free**, e deixe **Bound IP em branco**.
5. Cole o código gerado no `.env` na linha: `VULNERS_API_KEY=`

O motor do Draco lê esse arquivo nativamente e, automaticamente, utiliza os cabeçalhos de segurança mais atuais (como *X-Api-Key* e a API v2.0 do NVD).

---

## 💡 A ideia, com uma analogia

Cada computador na internet é uma **casa**. A casa tem **portas** (a 80 é a do
site, a 22 a do acesso remoto); atrás de cada porta aberta mora um **serviço** (um
programa), e programas têm **versões** — versões antigas costumam ter **falhas
conhecidas**. O Draco é o **inspetor** que anota as portas abertas, pergunta "quem
mora aqui e qual a idade?" e consulta um **catálogo público de falhas** para
avisar o que é perigoso.

---

## 📖 Conceitos essenciais (7 palavras que abrem tudo)

| Termo | O que é | Analogia |
|---|---|---|
| **IP** (`45.33.32.156`) | O endereço do computador na internet. | O CEP + número da casa. |
| **Porta** (`22`, `80`…) | Um canal de entrada numerado (existem 65.535). | As portas e janelas da casa. |
| **Estado** (aberta/fechada/filtrada) | Aberta = alguém atende; fechada = "não tem ninguém"; filtrada = firewall engoliu a batida. | Destrancada · trancada · muro que nem deixa bater. |
| **Serviço & Versão** (`OpenSSH 6.6.1`) | O programa que atende e sua versão exata. | O modelo e o ano do carro (decide o recall). |
| **Vulnerabilidade** | Um defeito de segurança que pode ser abusado. | Uma fechadura com defeito de fábrica. |
| **CVE** (`CVE-2016-1908`) | O número de identidade mundial de uma falha. | O número do recall daquele defeito. |
| **CVSS** (`0.0`–`10.0`) | A nota de gravidade (9–10 crítico; 7–8.9 alto; 4–6.9 médio). | A nota de risco do recall. |

---

## 🛠️ O time de ferramentas

O Draco é o **maestro**: ele não reinventa a roda, orquestra quatro ferramentas
famosas e junta tudo num relatório só.

| Ferramenta | Papel | Analogia |
|---|---|---|
| **Masscan** | Batedor veloz: acha **quais portas estão abertas** em segundos. | Passa correndo e anota as janelas acesas. |
| **Nmap** | Investigador: vai **só nas portas abertas** e descobre serviço, versão e SO (com técnicas furtivas). | Conversa em cada janela acesa. |
| **Nuclei** | Auditor de sites: se houver web (80/443), roda milhares de testes prontos. | Um checklist gigante de defeitos comuns. |
| **SearchSploit** | Arquivo de falhas **offline** (Exploit-DB local). | O fichário de recalls na oficina. |
| **O "Cérebro"** | A lógica que **reage** aos achados e consulta o **NVD** e **Vulners** (catálogo oficial de CVEs). | O inspetor-chefe que decide o próximo passo. |

---

## 🔀 O fluxo (o que um comando faz por baixo)

Cada etapa usa a saída da anterior — do mais leve ao mais profundo:

```mermaid
flowchart LR
    A[Alvo] -->|vivo?| B[Descoberta<br/>do host]
    B -->|IPs| C[Masscan<br/>portas abertas]
    C -->|portas| D[Nmap<br/>serviço + versão]
    D -->|CPE| E[Cérebro<br/>Nuclei + CVEs]
    E -->|CVEs| F([Relatório .md])
    B -.->|se DOWN| G[Relatório vazio]
    D -.->|sem resposta:<br/>refaz sem fragmentação| D
```

As setas tracejadas são as **decisões de segurança** do Cérebro: se o host está
**DOWN**, encerra e gera relatório vazio (não trava); se o Nmap furtivo **não
recebe resposta** ele **refaz automaticamente sem fragmentação** — um *fallback de confiabilidade*.

---

## ⚙️ Instalação

Testado em Ubuntu/Debian (inclusive WSL2). Um comando prepara tudo:

```bash
./setup_environment.sh     # binários + venv + registra o comando 'draco'
```

Instala `nmap`, `masscan`, `nuclei`, `searchsploit` e cria o
comando global `draco`. A ferramenta **degrada com log claro** se algum binário
faltar.

---

## ▶️ Como usar

```bash
draco                      # alvo padrão scanme.nmap.org
draco scanme.nmap.org      # um alvo
draco -f targets.txt       # arquivo de alvos
```

**Passo a passo:**

1. **Digite o comando** (uma das formas acima). Sem argumento → usa `scanme.nmap.org`.
2. **Digite a senha uma vez** — o Draco exige root e se eleva sozinho.
3. **Acompanhe os logs** `[DRACO-ENGINE]` na tela (cada passo em tempo real).
4. **Abra o relatório** em `outputs/relatorio_draco_<IP>_<DATA>.md`.

> **Autorização:** o alvo que você digita é auditado direto. A responsabilidade é sua: **só aponte o Draco para
> alvos que você tem permissão de testar.**

---

## 📄 Como ler o relatório (o mais importante)

Exemplo **real** gerado contra `scanme.nmap.org`. As quatro seções, em ordem:

### 1. Status Geral do Host

| IP | Status | Sistema Operacional | Tempo | Método |
|---|---|---|---|---|
| 45.33.32.156 | 🟢 UP | Linux 5.0 – 5.5 | 189ms | ICMP / TCP-connect:80 |

A casa está de pé (**UP**), é um Linux, respondeu rápido, confirmado por dois
métodos.

### 2. Mapeamento de Portas

| Porta | Estado | Razão | Serviço | Versão |
|---|---|---|---|---|
| 22 | 🟢 Aberta | `syn-ack` | SSH | OpenSSH 6.6.1p1 |
| 80 | 🟢 Aberta | `syn-ack` | HTTP | Apache httpd 2.4.7 |

A coluna **Razão** é o detalhe de ouro: `syn-ack` = "o servidor respondeu que a porta está aberta".

### 3. Vulnerabilidades e CVEs

| Porta / Serviço | CVE | Severidade | Fonte | O que é |
|---|---|---|---|---|
| 80 · Apache 2.4.7 | CVE-2017-7679 | 🔴 Crítica (9.8) | nvd | Leitura além do buffer no mod_mime. |

Cada linha é uma falha conhecida. A coluna **Fonte** diz de onde veio (`nvd` =
catálogo oficial, `vulners` = feeds atualizados de falhas, `searchsploit` = base local).

### 4. Vetores Recomendados

Próximos passos sugeridos, sempre em nível de **recomendação** defensiva. Um apêndice final lista **todos os comandos executados**, para você auditar exatamente o que a ferramenta fez.

---

## 🛡️⚔️ E com o laudo na mão?

- **Se você defende:** comece pelas críticas/altas. Para cada uma: **atualize** o
  programa, feche a porta se não precisa estar aberta, coloque firewall. O CVSS dá
  a ordem de prioridade.
- **Se você ataca (autorizado):** em pentest **com permissão por escrito**, o
  relatório é o mapa — os CVEs e vetores mostram por onde provar que a falha é
  real, sempre dentro do escopo.

> **A linha que não se cruza:** escanear sem autorização é ilegal na maioria dos
> países. Use no seu ambiente, em laboratórios, ou no `scanme.nmap.org`. Permissão primeiro, sempre.

---

## 🧪 Testes e lint

Não tocam a rede nem executam binários reais (usam saídas capturadas em `tests/fixtures/`):

```bash
./venv/bin/pytest -q          # 54 testes
./venv/bin/ruff check .       # lint
```

---

## 📁 O que é cada arquivo (você não precisa mexer em nada disso)

Você só usa o comando `draco`. E coloca as suas chaves opcionais no `.env`. O resto é
o motor interno que opera de maneira invisível e sem opções pra você se preocupar:

| Caminho | Papel |
|---|---|
| `draco.sh` | O lançador (o comando `draco` aponta para cá; eleva a root e lê o .env). |
| `outputs/` | Onde os relatórios `.md` são salvos. |
| `draco/cli.py` · `engine.py` | Entrada e o "maestro" do pipeline. |
| `draco/ingest.py` · `discovery.py` | Lê/valida alvos · host UP/DOWN. |
| `draco/scanner.py` · `parser.py` | masscan+nmap · lê as saídas → dados. |
| `draco/brain.py` · `correlation.py` | Decide os próximos passos · CVEs. |
| `draco/reporter.py` | Gera o relatório `.md`. |

---

## ⚖️ Aviso legal

Ferramenta para **auditoria autorizada, pesquisa de segurança e uso defensivo**.
O uso contra sistemas sem autorização é ilegal. Você é responsável por respeitar
o escopo acordado e a legislação aplicável.
