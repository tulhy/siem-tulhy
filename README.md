# SIEM Tulhy

SIEM defensivo para redes Windows pequenas, escrito em Python. Um agente em cada computador coleta processos, arquivos, conexões de rede e logs do Windows. Um servidor FastAPI recebe esses dados, aplica regras e correlação e mostra tudo num painel web: agentes, eventos, alertas e exclusões.

> **Versão de demonstração.** Os tokens padrão são simples de propósito: **123** para o administrador e **456** para a aba Exclusões. Troque os dois antes de usar em uma rede real (veja [Trocar os tokens](#trocar-os-tokens)).

## O que ele faz

- **Agente Windows** com fila offline (SQLite). Nada se perde se o servidor ficar fora do ar.
- **Envio seguro**: HTTPS com certificado próprio, Bearer e assinatura HMAC por requisição, proteção contra reenvio.
- **Regras em JSON** que podem ser editadas sem reiniciar: portas sensíveis, acesso remoto (RDP/SSH/VNC/WinRM), scripts (.py, .vbs, .htm, .bat), varredura de portas, picos de conexões, processos em pastas temporárias e mais.
- **Painel web** em português, com explicação e orientação em cada alerta.
- **Aba Exclusões**, protegida por um segundo token:
  - ignora pastas, extensões, programas ou IPs remotos, em uma máquina ou em todas;
  - cada exclusão pode ter **prazo de validade** e ser renovada;
  - toda alteração pede o token de novo e fica no **histórico**, que não pode ser apagado pelo painel;
  - depois de 5 tokens errados em 15 minutos, aquele computador fica **bloqueado por 15 minutos**.
- **Rede local** por cabo e Wi-Fi ao mesmo tempo, com CA própria e troca automática de endereço no agente.
- **Instaladores `.exe`** (PyInstaller) para criar outra unidade e cadastrar agentes com código de cadastro.
- **Exportação** de eventos e alertas para CSV.

O Tulhy ajuda a investigar. **Nenhum SIEM garante 100% de detecção**, e um alerta é um sinal para revisar, não uma prova de ataque.

## Começar (Windows, Python 3.12+)

1. Baixe o repositório e dê dois cliques em **`INICIAR_LOCAL.cmd`**. Na primeira vez ele cria o ambiente `.venv` e instala as dependências (precisa de Internet).
2. Espere a mensagem de que o servidor iniciou e mantenha a janela aberta.
3. Abra **http://127.0.0.1:8000/** e entre com o token **123**.
4. Para a aba **Exclusões**, use o token **456**.

Para rodar manualmente:

```bash
py -3 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m scripts.local_lab
```

Para monitorar outros computadores da rede, veja [docs/REDE_LOCAL.md](docs/REDE_LOCAL.md): rode `INICIAR_REDE.cmd` no servidor e `CRIAR_AGENTE.cmd` para gerar o pacote de cada máquina.

## Trocar os tokens

Os tokens ficam em `data/local-lab/admin-token.txt` (administrador) e `data/local-lab/exclusion-token.txt` (exclusões). Esses arquivos são criados na primeira execução. Para trocar:

1. Pare o SIEM (`PARAR_SIEM.cmd` ou Ctrl+C).
2. Edite os dois arquivos com textos longos e diferentes. Por exemplo, gere cada um com `py -c "import secrets; print(secrets.token_urlsafe(48))"`.
3. Inicie de novo.

Em Docker ou nuvem, use as variáveis `SIEM_ADMIN_TOKEN` e `SIEM_EXCLUSION_TOKEN` (veja `.env.example`).

## Estrutura

| Pasta | Conteúdo |
|---|---|
| `agent/` | Agente Windows: coletores, normalização, fila offline e envio |
| `server/` | API FastAPI, ingestão, motor de detecção, correlação e alertas |
| `dashboard/` | Painel web (HTML, CSS e JavaScript sem frameworks) |
| `rules/` | Regras e políticas em JSON (`regras_de_alertas.json` e outras) |
| `scripts/` | Inicialização, rede local, instaladores, certificados e exportação |
| `shared/` | Protocolo e modelos usados pelo agente e pelo servidor |
| `tests/` | Testes automáticos (pytest) |
| `docs/` | Manual completo, rede local, agente em segundo plano e segurança |
| `*.cmd` | Atalhos para Windows: iniciar, parar, status, criar agente, exportar |

## Testes

```bash
.venv\Scripts\python -m pytest -q
```

## Documentação

- [Manual completo](docs/MANUAL.md)
- [Rede local](docs/REDE_LOCAL.md)
- [Agente em segundo plano](docs/AGENTE_SEGUNDO_PLANO.md)
- [Segurança](docs/SECURITY.md)
- [Validação](docs/VALIDATION.md)

## Licença

[MIT](LICENSE). O agente inclui a biblioteca [pypdf](https://github.com/py-pdf/pypdf) (BSD) em `agent/collectors/pdf_library.zip`.
