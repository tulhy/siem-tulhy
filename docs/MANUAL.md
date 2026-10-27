# SIEM Tulhy

SIEM defensivo em Python 3.12+, com agente Windows autônomo, fila offline SQLite, API FastAPI, motor de regras/correlação e dashboard. Projeto executável para laboratório e implantações pequenas, com caminho de hospedagem em nuvem. Não é uma solução EDR certificada nem substitui controles preventivos ou uma operação de resposta a incidentes.

**Nenhum SIEM garante 100% de detecção ou zero falsos negativos.** Os padrões priorizam sensibilidade e registram falhas de cobertura. Alertas apresentam evidências e hipóteses, não uma afirmação automática de malware.

## Começar de forma simples no Windows

1. Abra a pasta do projeto e execute **INICIAR_LOCAL.cmd** com duplo clique.
2. Aguarde a mensagem `Tulhy local started`. Mantenha a janela aberta.
3. Acesse **http://127.0.0.1:8000/** no navegador.
4. Abra `data/local-lab/admin-token.txt`, copie o token e cole no campo de acesso do dashboard. Esse arquivo é privado; não o compartilhe.
5. Em **Agentes**, a máquina deve ficar online. Em **Eventos**, confira os registros coletados. A primeira coleta pode levar alguns segundos.

O iniciador cria o certificado local, sobe API HTTPS em 8443 e dashboard de loopback em 8000, cadastra a máquina e inicia o agente. As credenciais e os dados são preservados para as próximas execuções. Nenhum serviço é instalado, e nenhuma porta é exposta na Internet. Encerre com **Ctrl+C** na janela; execute novamente o mesmo arquivo para retomar.

O `.cmd` usa `.venv`, ou o ambiente já preparado nesta entrega. Se não houver ambiente, tenta criá-lo com o Python Launcher (`py`) e instalar as dependências; nesse caso é necessário Python 3.12+ e Internet para o pip. Não é necessário Docker para este modo.

Alternativa com um ambiente Python configurado: `python -m scripts.local_lab`. O argumento `--check` exercita o fluxo com dados sintéticos e encerra sem coletar a máquina; use um `--data-dir` separado para esse teste. Configuração específica do iniciador fica em `data/local-lab/agent-config.yaml`. Os procedimentos das seções seguintes descrevem a execução manual e implantação em nuvem.

## 1. Arquitetura e garantias

**Executar o servidor em segundo plano:** pare a janela atual com Ctrl+C e abra `INICIAR_SEGUNDO_PLANO.cmd`. Após confirmar a inicialização, pode fechar a janela. Ele reutiliza o IP da última execução em rede; se ainda não foi configurado, começa em loopback. `STATUS_SIEM.cmd` mostra o estado e `PARAR_SIEM.cmd` solicita parada dos componentes preservando dados. Os logs ficam em `data/local-lab`. Esse modo não instala serviço nem inicia automaticamente após reiniciar o Windows. Para o **agente** como serviço com início automático, veja a seção 9.

**Outros computadores na mesma rede:** consulte [o passo a passo de rede local](REDE_LOCAL.md). Use `INICIAR_REDE.cmd` neste servidor e `CRIAR_AGENTE.cmd` para gerar um pacote individual por computador; no destino, execute `INICIAR_AGENTE.cmd` do pacote. A modalidade local padrão permanece restrita a loopback.

```text
Máquina Windows
  psutil / watchdog / Event Log / registro (somente leitura)
    → normalizador Pydantic
    → outbox SQLite (WAL + synchronous=FULL)
    → lotes JSON, gzip, HTTPS validado, Bearer + HMAC
Internet
    → Caddy (TLS) → FastAPI → PostgreSQL / SQLite
                               ├── eventos persistidos → ACK com event_ids
                               ├── worker → regras + baseline + correlação → alertas
                               └── heartbeat → detecção de perda de telemetria
Dashboard → API autenticada → agentes / eventos / alertas / métricas
```

- O agente não abre o dashboard nem depende dele. O envio roda em thread separada da coleta.
- A fila só remove IDs explicitamente confirmados após o commit no servidor. ACK perdido causa retransmissão idempotente.
- O servidor grava eventos com processamento pendente. Reiniciar o worker não elimina esse trabalho.
- O transporte é **at-least-once** com deduplicação. Não há promessa de exactly-once em todos os sensores: polling e Event Log podem observar a mesma atividade sob IDs diferentes.
- Dados atrasados mantêm o horário original; a assinatura usa o horário atual da requisição. Correlaciona-se pelo horário do evento, por máquina e, quando configurado, usuário/processo/ProcessGuid.
- Banco indisponível, erro de commit ou ACK inválido não limpam a fila.
- Limites físicos são finitos: ao atingir a capacidade configurada, novos eventos podem ser recusados. A fila preserva os existentes e guarda contador durável de perdas em área separada, emitindo `telemetry.integrity` quando o envio voltar. Disco realmente cheio ou falha de hardware ainda podem impedir qualquer gravação.

## 2. Estrutura

```text
agent/
  main.py                 Loop autônomo, coleta e transporte
  windows_service.py      Host de serviço pywin32
  collectors/             Processos, rede, recursos, arquivos, Windows e autostart
  normalizers/            Formato comum e redução de dados sensíveis
  queue/persistent.py     Outbox, estado de cursores, perdas e métricas
  transport/client.py     HTTPS, HMAC, compressão, ACK e backoff
  config/                 Configuração validada
  utils/                  SHA-256 com cache e limite de tamanho
shared/                   Esquemas, protocolo e logging
server/
  main.py                 Aplicação FastAPI e ciclo de vida
  api/                    Rotas, autenticação e limites ASGI
  database/               Engine e sessões SQLAlchemy
  models/                 Tabelas e índices
  schemas/                Contratos administrativos
  detection/              DSL de regras, engine e baseline
  correlation/            Sequências, janelas e risco
  alerts/                 Explicação e deduplicação de alertas
  services/               Ingestão, worker e monitor de heartbeat
dashboard/templates/      HTML
dashboard/static/         CSS/JS sem dependências externas
rules/default_rules/      Regras JSON/YAML
rules/risk.json           Pesos, limites e janela do risco
scripts/                  Instalação, cadastro, certificado e eventos sintéticos
tests/                    Testes unitários e de integração HTTPS
docs/                     Segurança e relatório de validação
```

## 3. Requisitos

- Python **3.12 ou superior**. As versões fixadas foram exercitadas com 3.12.14 no Windows.
- Windows 10/11 ou Windows Server para o agente completo. Outros sistemas têm somente coletores portáveis; serviço e Windows Event Log são específicos de Windows.
- Ambiente virtual para desenvolvimento. Para **serviço Windows**, Python global instalado para todos os usuários, em local acessível ao SYSTEM.
- PostgreSQL 16 no Compose; SQLite para desenvolvimento. Docker Engine/Desktop com Compose v2 para a implantação empacotada.
- HTTPS público com certificado válido; DNS e portas 80/443 disponíveis para o Caddy obter o certificado.
- Sincronização de relógio. Requisições assinadas toleram ±300 segundos.
- Auditoria do Windows, canais de PowerShell e Sysmon são pré-requisitos opcionais de cobertura. O projeto **não altera** políticas de auditoria nem instala Sysmon automaticamente.

## 4. Instalação para desenvolvimento

Abra um terminal na pasta que contém este README:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Em Linux: `source .venv/bin/activate`. Para instalar apenas o servidor, use `requirements-server.txt`; apenas o agente, `requirements-agent.txt`. `requirements.txt` reúne ambos; ferramentas de teste e geração de certificado ficam em `requirements-dev.txt`.

**Segredos não têm valores padrão.** Gere um token administrativo e mantenha-o no terminal/cofre de segredos:

```powershell
$env:SIEM_ADMIN_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DATABASE_URL = 'sqlite:///data/server.db'
```

Não grave tokens em comandos compartilhados, screenshots, Git, logs ou no `config.yaml`. `.env.example` é somente um modelo; `uvicorn` e os módulos Python **não carregam `.env` automaticamente**. Compose carrega `.env` na pasta do projeto.

## 5. Servidor local e dashboard

Execução solicitada, apropriada atrás de proxy TLS/firewall:

```powershell
uvicorn server.main:app --host 0.0.0.0 --port 8000
```

Para desenvolvimento sem exposição à rede, prefira:

```powershell
uvicorn server.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Acesse **http://127.0.0.1:8000/** e informe o token administrativo. A página HTML pode ser aberta sem token, mas todas as consultas de telemetria exigem autenticação. O token fica somente na memória da aba, não em cookies, URLs ou `localStorage`; recarregar exige novo login. O botão Sair limpa a sessão local. Não envie tokens pela Internet usando HTTP.

O dashboard apresenta totais, online/offline, eventos em 24h, alertas ativos/críticos, série temporal, severidades, tipos e máquinas. As páginas têm paginação de 100 registros. Eventos aceitam filtros por início/fim, hostname, usuário, tipo, severidade, processo, SHA-256, IP local/remoto, porta e estado da detecção. Filtros textuais são exatos; horários da interface são convertidos para UTC na consulta. Um evento `clear` significa “nenhuma regra acionada”, **não** “atividade comprovadamente segura”.

Em Alertas, abra um registro para ver motivo, condições, janela, threshold, contexto de agrupamento, MITRE, IDs e eventos completos normalizados. A resolução manual não elimina a evidência.

## 6. HTTPS de laboratório, sem desativar TLS

O agente **recusa URLs HTTP**, inclusive localhost. Para testá-lo localmente, gere um certificado de curta duração:

```powershell
python -m scripts.dev_certificate --output data/tls
$env:SIEM_CA_BUNDLE = (Resolve-Path data/tls/localhost.pem).Path
uvicorn server.main:app --host 127.0.0.1 --port 8443 --ssl-certfile data/tls/localhost.pem --ssl-keyfile data/tls/localhost-key.pem --no-access-log
```

Defina também `SIEM_ADMIN_TOKEN` e `DATABASE_URL` nesse terminal. Para usar simultaneamente o dashboard HTTP de loopback, pode manter a instância de 8000 em outro terminal com **o mesmo banco e token**; os workers serializam o processamento por agente. Essa disposição é apenas para laboratório, com baixo volume.

O certificado é aceito pelo agente e pelo script de cadastro somente quando `SIEM_CA_BUNDLE` aponta para ele. Não há `verify=False`. O navegador não confia automaticamente nesse certificado; use o dashboard HTTP de loopback no laboratório, ou um domínio/certificado confiável. O script não modifica o repositório de certificados do Windows.

## 7. Cadastrar a máquina e executar o agente

Cadastre usando exatamente o hostname que o agente enviará. Com `agent_name: ''`, ele usa `socket.gethostname()`.

Em um terminal administrativo de cadastro, com a CA e token administrativo já definidos:

```powershell
$machineName = python -c "import socket; print(socket.gethostname())"
python -m scripts.register_agent --server https://localhost:8443 --hostname $machineName --output data/agent-credentials.json
```

O arquivo é criado com acesso restrito (ACL no Windows; modo 0600 em POSIX), sem imprimir o token. O servidor guarda apenas o hash do token. Se a requisição de cadastro for confirmada pelo servidor mas a resposta se perder, o cadastro pode ficar órfão: liste os agentes e desabilite o cadastro sem credencial antes de repetir.

No terminal do agente:

```powershell
$credentials = Get-Content data/agent-credentials.json -Raw | ConvertFrom-Json
$env:SIEM_AGENT_ID = $credentials.agent_id
$env:SIEM_AGENT_TOKEN = $credentials.agent_token
$env:SIEM_CA_BUNDLE = (Resolve-Path data/tls/localhost.pem).Path
python -m agent.main
```

Em produção, use `https://seu-dominio` e dispense `SIEM_CA_BUNDLE` quando houver CA pública confiável. Não deixe o token administrativo no ambiente de execução do agente: ele precisa somente da própria identidade e token. Cadastre cada máquina separadamente. Não clone uma fila/credencial para várias máquinas.

`Ctrl+C` para o processo, encerra o observador de arquivos e mantém os eventos pendentes. Não execute duas instâncias do agente com a mesma pasta de dados: a fila suporta produtores em threads, mas a coordenação dos sensores pressupõe uma instância por máquina.

## 8. Configuração do agente

Edite `config.yaml` ou use `SIEM_AGENT_CONFIG` para apontar para outro arquivo.

| Opção | Padrão | Efeito |
|---|---:|---|
| `server_url` | `https://localhost:8443` | Origem HTTPS, sem usuário/senha/query |
| `agent_name` | vazio | Hostname cadastrado; vazio usa o sistema |
| `collection_interval` | 5s | Polling de processos/rede/Windows/recursos |
| `batch_size` | 100 | Até 200 eventos; transporte também limita bytes |
| `heartbeat_interval` | 30s | Comunica saúde e fila pendente |
| `queue_max_size` | 100000 | Quantidade máxima de eventos normais na outbox |
| `queue_max_bytes` | 256000000 | Limite de payload serializado na outbox |
| `data_dir` | `data/agent` | Fila, cursores, métricas e logs rotacionados |
| `timeout` | 15s | Timeout HTTP por operação |
| `monitor_paths` | `[]` | Diretórios de segurança escolhidos explicitamente |
| `collect_command_lines` | false | Opt-in; redaction por padrões, sem garantia de remover todo segredo |
| `hash_max_bytes` | 50000000 | Não ler executáveis maiores que esse limite |
| `windows_lookback_seconds` | 300s | Lookback inicial de Event Log, antes de existir cursor |
| `windows_events` | true | Event Log e observação de Run/RunOnce |
| `cpu_threshold` / `memory_threshold` / `disk_threshold` | 90/90/95% | Anomalias de uso; disco representa ocupação, não latência de I/O |

`SIEM_SERVER_URL` pode sobrescrever `server_url`. Segredos ficam em `SIEM_AGENT_ID` e `SIEM_AGENT_TOKEN`. O serviço usa arquivo separado protegido por ACL.

Não monitore o próprio `data_dir`: isso gera um ciclo de eventos de arquivo causados pela fila. Evite diretórios pessoais e discos inteiros. Ajuste sensores e regras com dados representativos; aumentar indiscriminadamente a coleta pode saturar o sistema e prejudicar a cobertura.

O limite em bytes é **lógico**, não o tamanho exato de `queue.db` no disco. SQLite inclui índices, páginas livres e WAL; reserve margem adicional e alarme de espaço livre. As páginas são reutilizadas. Logs têm rotação de 2 MB + três cópias. A área reservada de integridade guarda um evento em trânsito e agrega novas perdas em contador. O contador de perdas representa tentativas recusadas de entrada; logs Windows que ainda existirem podem ser relidos posteriormente.

## 9. Instalar como serviço Windows

Instale Python 3.12+ **para todos os usuários**, por exemplo `C:\Program Files\Python312\python.exe`. Abra PowerShell como Administrador. Defina `SIEM_AGENT_ID` e `SIEM_AGENT_TOKEN` por leitura do arquivo de credenciais, como acima.

```powershell
.\scripts\windows-agent.ps1 -Action Install -Python 'C:\Program Files\Python312\python.exe' -Config .\config.yaml
# Laboratório com CA particular:
.\scripts\windows-agent.ps1 -Action Install -Python 'C:\Program Files\Python312\python.exe' -Config .\config.yaml -CAFile .\data\tls\localhost.pem
```

Execute **uma** das alternativas. A instalação:

1. Copia `agent` e `shared` para `%ProgramFiles%\Tulhy`.
2. Restringe diretórios a SYSTEM e Administradores antes de gravar credenciais.
3. Instala dependências no Python global e executa `pywin32_postinstall`.
4. Cria `tulhy-service.pth` no site-packages desse Python, apontando para o código instalado.
5. Salva configuração e credenciais em `%ProgramData%\Tulhy`; fila/logs ficam em `data` abaixo dele.
6. Registra serviço visível `TulhyAgent`, início automático, LocalSystem e recuperação por reinício.

```powershell
.\scripts\windows-agent.ps1 -Action Status
.\scripts\windows-agent.ps1 -Action Stop
.\scripts\windows-agent.ps1 -Action Start
.\scripts\windows-agent.ps1 -Action Uninstall -Python 'C:\Program Files\Python312\python.exe'
```

Também pode usar `services.msc`. O projeto não esconde o processo. LocalSystem aumenta a visibilidade e também o impacto de comprometimento do agente: mantenha o código protegido e avalie conta de serviço com privilégios mínimos para sua cobertura. `HKCU` sob LocalSystem representa essa conta; não cobre automaticamente Run/RunOnce de todos os usuários.

Desinstalar **preserva** fila, configurações, credenciais, código e o `.pth`, para não apagar telemetria pendente. Revogue/desabilite a credencial no servidor. Após exportar/reconciliar pendências, remova manualmente os diretórios e `tulhy-service.pth`. Dependências globais não são removidas, pois podem ser compartilhadas.

Atualização: pare/desinstale o serviço, faça backup da fila e reinstale usando a mesma identidade/configuração. Teste primeiro em homologação. O instalador não modifica políticas de execução do PowerShell, firewall, auditoria ou segurança do Windows.

## 10. Docker e nuvem

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
# Use um segredo gerado para SIEM_ADMIN_TOKEN; gere outro para POSTGRES_PASSWORD.
# Edite SIEM_DOMAIN e ACME_EMAIL em .env.
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 server
```

Use senha PostgreSQL hexadecimal gerada, evitando caracteres que precisariam ser escapados na URL. Não publique o conteúdo de `docker compose config` sem `--quiet`, pois ele inclui variáveis resolvidas.

O DNS do domínio deve apontar para o host. Caddy termina HTTPS e renova certificados; apenas 80/443 são publicados. Servidor e PostgreSQL ficam na rede privada interna. O contêiner da API roda como usuário sem privilégios, filesystem somente leitura e capacidades removidas. PostgreSQL usa volume persistente. **Não use `docker compose down -v` para manutenção normal**: isso remove os volumes com dados.

Dashboard: `https://seu-dominio/`. Health: `https://seu-dominio/health`. Agentes usam essa mesma origem HTTPS. O HTTP entre proxy/API ocorre apenas na rede interna do Compose; para hosts separados, use TLS também entre componentes.

O IP exibido no Compose é o peer observado pela API, normalmente o proxy. Cabeçalhos de cliente não são confiados automaticamente. Para exibir IP original, configure explicitamente proxies confiáveis na sua infraestrutura; nunca aceite `X-Forwarded-For` de qualquer origem.

Antes de produção: valide Docker/PostgreSQL, recursos sob carga, recuperação de backup e serviço Windows no ambiente real. O relatório em `docs/VALIDATION.md` distingue testes executados e pendentes. As imagens usam tags de major; fixe digests em uma implantação controlada após avaliar atualizações.

## 11. API e autorização

| Método e rota | Autorização | Função |
|---|---|---|
| `POST /api/v1/agents/register` | Administrador | Emite credencial individual uma vez |
| `PATCH /api/v1/agents/{id}` | Administrador | `{"enabled": false}` revoga uso |
| `POST /api/v1/agents/{id}/rotate-token` | Administrador | Substitui token e retorna novo |
| `POST /api/v1/events` | Agente assinado | Evento individual |
| `POST /api/v1/events/batch` | Agente assinado | `{"events": [...]}` |
| `POST /api/v1/agents/heartbeat` | Agente assinado | Versão, OS, fila e métricas |
| `GET /api/v1/agents` | Administrador | Lista paginada |
| `GET /api/v1/events` | Administrador | Filtros + `offset`, `limit` até 500 |
| `GET /api/v1/alerts` e `/{id}` | Administrador | Lista e evidências |
| `PATCH /api/v1/alerts/{id}` | Administrador | `active` ou `resolved` |
| `GET /api/v1/dashboard/stats` | Administrador | Agregações |
| `GET /api/v1/rules` | Administrador | Regras carregadas |
| `GET /api/v1/metrics` | Administrador | Saúde da telemetria e detecção |
| `GET /health` | Público | Banco e worker; 503 se detecção degradada |

Administrador: `Authorization: Bearer <SIEM_ADMIN_TOKEN>`. O agente adiciona Bearer individual, `X-Agent-ID`, `X-Timestamp` (Unix segundos), `X-Nonce` (UUID) e `X-Signature`.

```text
HMAC-SHA256(token, METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256(wire_body))
```

A assinatura cobre os bytes efetivamente enviados, incluindo gzip. O servidor valida token, assinatura, relógio e unicidade do nonce; nonces ficam no banco até expirar a janela. O token não é guardado em texto no banco. Repetir um nonce confirmado retorna 409. Retry legítimo mantém `event_id`, mas cria timestamp e nonce novos.

Limites: 1 MiB transmitido, 2 MiB descomprimido, 200 eventos/lote e 180 requisições confirmadas por minuto/agente. Timestamps de evento mais de cinco minutos no futuro são rejeitados; eventos antigos são aceitos. JSON não conhecido e campos inválidos geram 422 sem refletir conteúdo sensível. Um ID já existente com conteúdo diferente gera 409 e não é confirmado.

O limitador por agente é transacional e persistente. Proteção de borda contra tráfego anônimo/DDoS precisa de firewall, gateway/WAF e limites de conexão adequados; o Compose inclui timeouts e limite de corpo, mas não um WAF distribuído.

## 12. Regras, correlação, baseline e risco

Crie um arquivo `.json`, `.yaml` ou `.yml` em `rules/default_rules`. Um arquivo contém um objeto ou lista. Exemplo:

```yaml
id: AUTH_FAILURE_BURST_CUSTOM
name: Falhas de autenticação por usuário
description: Cinco falhas em cinco minutos; investigar origem e contexto.
category: credential_access
severity: HIGH
confidence: MEDIUM
enabled: true
conditions:
  - {field: event_type, value: auth.failure}
group_by: [user]
threshold: 5
window_seconds: 300
tags: [authentication, behavior]
mitre: [T1110]
```

Reinicie o servidor após editar regras. Erros de schema, IDs duplicados e diretório sem regras impedem o início, evitando operar silenciosamente sem detecção. Desative com `enabled: false`. As definições são sincronizadas na tabela `rules`; não há editor remoto de regras.

Condições são AND, com campos permitidos e operadores `eq`, `ne`, `contains`, `contains_any`, `in`, `gte`, `exists`, `cidr`. Strings são comparadas sem distinção de maiúsculas. Campos ausentes não satisfazem condições normais, nem `ne`; use `exists` para testar ausência. Não se usa `eval`, código Python em regras ou regex arbitrárias.

`sequence` é uma lista de etapas; cada etapa é uma lista de condições AND. Eventos diferentes devem satisfazer as etapas em ordem temporal dentro da janela. `conditions` seleciona os eventos elegíveis para a sequência. Se `sequence` estiver presente, ela define a correlação; use `threshold: 1`. Para thresholds, todos os eventos da evidência devem caber na janela.

`group_by` pode incluir usuário, PID, instante de criação, nome do processo, IP remoto ou `raw_event.process_guid`. Valores de agrupamento ausentes não juntam eventos de entidades diferentes. PID sozinho pode ser reutilizado: prefira PID + instante de criação ou ProcessGuid do Sysmon. Eventos com horários idênticos recebem desempate determinístico por ID; isso não prova a ordem real de sensores distintos.

Padrões inclusos: falhas de autenticação por usuário e por máquina, muitas conexões por processo, execução temporária, execução temporária seguida de rede (polling e Sysmon), persistência, arquivos monitorados, sinais PowerShell, recursos e integridade. Indicador de hash sintético fica desativado; você deve fornecer indicadores conhecidos confiáveis, com revisão de validade. A alteração do indicador não instala/baixa nenhum arquivo.

Baseline: aprende combinações processo/destino por agente. Após pelo menos 30 observações e uma hora de histórico, um destino novo produz alerta MEDIUM. É um baseline simples, não machine learning e não uma lista de confiança. As regras comportamentais continuam ativas durante o aprendizado. Aprendizagem pode ser contaminada; não trate destinos vistos como seguros.

`rules/risk.json` controla pesos e janela: LOW=10, MEDIUM=25, HIGH=50, CRITICAL=80; risco acumulado por agente em uma hora, limitado a 100. Evidências anteriores podem elevar a confiança; severidade original da regra permanece visível. Cada correspondência tem ligação à regra, evento e alerta. Janelas sobrepostas podem produzir alertas adicionais para novas evidências; isso prioriza sensibilidade e exige ajuste operacional. O risco não é uma probabilidade e alertas históricos não são recalculados retroativamente por chegadas tardias.

## 13. Testes e demonstração benigna

```powershell
python -m pytest -q
python -m pytest tests/test_https_integration.py -v
```

Os testes cobrem normalização, redaction, schema, coletores com fixtures, hashing, fila após reinício, capacidade, perdas enquanto ACK está em trânsito, autenticação, adulteração, replay, rotação/revogação, gzip e bomba de descompressão, lote atômico, deduplicação, filtros, regras, thresholds, agrupamento, eventos atrasados, baseline, risco, heartbeat, worker e dashboard.

A integração HTTPS gera certificado temporário, sobe Uvicorn real em porta efêmera, perde deliberadamente a resposta após commit e retransmite com o mesmo ID. Também comprova que um cliente sem a CA rejeita o certificado.

Para testar visualmente sem malware, cadastre um **agente separado de laboratório**, crie configuração com `agent_name` igual ao hostname cadastrado e carregue apenas suas credenciais:

```powershell
python -m scripts.synthetic_events
```

São enviados somente metadados sintéticos: falhas de autenticação, nome de executável fictício, IP documental `192.0.2.10` e arquivo fictício. O script não cria processos suspeitos, não altera persistência, não conecta ao IP sintético e não modifica esse arquivo. Deve gerar regras de autenticação, execução temporária, correlação e integridade de arquivo.

## 14. Operação, métricas e recuperação

- Agente: `events_collected`, `events_sent`, `events_failed` (tentativas de lote que falharam), `events_pending`, `events_dropped_capacity`. Contadores persistem em SQLite e seguem no heartbeat.
- Servidor: `events_processed`, `events_detection_pending`, `alerts_generated`, `agent_last_seen`. Consulte `/api/v1/metrics` com token administrativo. Não é endpoint Prometheus; um coletor pode consumir o JSON.
- `last_seen` registra requisições válidas; `last_heartbeat` é separado. Online e `TELEMETRY_LOST` usam heartbeat, mesmo se outros eventos ainda chegarem.
- O monitor verifica a cada 15s, com timeout padrão de 120s. Um agente recém-cadastrado sem primeiro heartbeat também gera alerta após o período de tolerância. Desabilitados não são monitorados como falha. O retorno do heartbeat resolve alertas ativos de telemetria perdida.
- Logs da aplicação são JSON. Agente usa arquivo rotacionado; servidor escreve no stdout. Mensagens não incluem bodies, scripts, tokens ou credenciais; SQLAlchemy oculta parâmetros nas exceções. Logs padrão de startup do Uvicorn podem ter seu próprio formato.

**Falha de comunicação:** confira certificado, CA, DNS, relógio, token e hostname cadastrado; observe `agent.log`, tamanho/contador da fila e `/health`. Retry tem backoff exponencial com jitter, até aproximadamente seis minutos. Heartbeat continua tentando no intervalo, sem aguardar o backoff de eventos.

**400/401/403/409/422 persistentes:** o agente preserva o lote e registra falha; não remove automaticamente eventos inválidos. Corrija causa/configuração ou exporte e revise a fila com serviço parado. Um evento permanentemente inválido pode bloquear o restante daquele lote; não há descarte silencioso nem interface de quarentena nesta versão.

**Backup:** use `pg_dump`/`pg_restore` no PostgreSQL e teste restauração. Para SQLite, pare o componente e copie banco após encerramento/checkpoint, ou use a API de backup SQLite; não copie só o `.db` de um banco ativo ignorando WAL. Para o agente, backup inclui fila/cursores e identidade protegida. Perder o banco central após um ACK requer recuperação do backup: o agente já pode ter removido sua cópia.

**Retenção:** não há exclusão automática de eventos, alertas ou heartbeats nesta versão. Planeje capacidade e retenção com exportação/backup. Não exclua eventos pendentes de detecção. Remover históricos limita correlação de eventos offline muito antigos, evidências e pesquisa. SQLite é destinado a laboratório/baixo volume. Para volume maior, use PostgreSQL e avalie particionamento, retenção e worker dedicado antes de escalar.

**Schema:** versão inicial, criada com SQLAlchemy `create_all`. Isso cria tabelas ausentes; não migra tabelas existentes. Alterações futuras precisam de migrações versionadas e backup; nunca suponha que atualizar o código altera o schema automaticamente. Use uma base nova ao comparar rascunhos de desenvolvimento.

## 15. Limitações e segurança

- Polling perde processos/conexões que começam e terminam entre amostras. Combine Event Log/Sysmon habilitados e intervalos adequados; não há coleta ETW em tempo real.
- Canais desabilitados, permissões, rotação/limpeza e backlog além da retenção do Windows podem causar lacunas. Cursores persistem por canal; um reset observado gera integridade. Limpeza seguida de crescimento rápido além do cursor pode escapar desse mecanismo.
- O coletor lê até 128 eventos relevantes por canal por ciclo. Ajuste intervalo/canais/retenção para não ficar atrás do volume. O hash é limitado por tamanho e cache; arquivos inacessíveis/maiores ficam sem hash. Há corrida entre leitura e alteração do executável.
- O primeiro polling de processos/serviços registra uma fotografia do que já existe; não prova que tudo iniciou naquele instante. Eventos usam `observed_by_polling` quando aplicável.
- Watchdog não fornece diário durável completo de alterações; ausência do agente ou overflow interno do sistema pode causar perdas. Apenas metadados são guardados.
- Run/RunOnce e os eventos observados não cobrem todas as técnicas de persistência. Nem toda mudança de registro tem processo/usuário atribuível; não é inventada uma ligação causal.
- PowerShell é inspecionado em memória por sinais e só os nomes desses sinais são armazenados. Comandos privados, blocos de script e mensagens completas não são exportados.
- Linha de comando é opt-in. Redaction é limitada a padrões; segredos arbitrários podem escapar. Não habilite sem política de dados e avaliação de necessidade.
- Arquivos da fila/banco não têm criptografia implementada na aplicação. Use ACL, BitLocker/criptografia de volume e backups protegidos.
- Agente comprometido pode forjar dados ou parar a coleta. Heartbeat detecta ausência, não prova integridade criptográfica do endpoint. Não há tamper protection, atestação, resposta ativa ou execução remota.
- Autorização inicial tem dois papéis: administrador e agente. Não há SSO, MFA, múltiplos usuários analistas, RBAC granular ou isolamento multi-tenant. Restrinja a administração com VPN/proxy corporativo quando necessário.
- Não há feeds automáticos de inteligência, notificações e-mail/Slack, isolamento de host ou comandos remotos. Alertas ficam no banco/API/dashboard.
- A correlação consulta janelas no banco e materializa candidatos; janelas muito largas/alta taxa aumentam CPU/RAM. Faça teste de carga representativo. Não foi declarado limite de EPS sem medição.
- Não coleta teclas, senhas intencionalmente, cookies, credenciais, mensagens privadas nem arquivos pessoais completos. Não existe reverse shell, download/execução remota ou controle da máquina.

Veja `docs/SECURITY.md` e `docs/VALIDATION.md` para controles e escopo validado.

## Referências técnicas

- [Ciclo de vida FastAPI](https://fastapi.tiangolo.com/advanced/events/)
- [SQLAlchemy: conflitos em SQLite](https://docs.sqlalchemy.org/en/20/dialects/sqlite.html)
- [pywin32: instalação e Windows Service](https://github.com/mhammond/pywin32#running-as-a-windows-service)
- [API Windows Event Log do pywin32](https://timgolden.me.uk/pywin32-docs/win32evtlog.html)
- [Inicialização e healthchecks no Compose](https://docs.docker.com/compose/how-tos/startup-order/)
- [Diretivas do Caddy](https://caddyserver.com/docs/caddyfile/directives)

## Agentes sem terminal e identidade OR2

Os pacotes individuais novos incluem INSTALAR_SERVICO.cmd. Para instalação automática com o Windows e atualização de pacotes antigos, consulte [Agente em segundo plano](AGENTE_SEGUNDO_PLANO.md). O dashboard utiliza a logo OR2 fornecida, verde escuro e amarelo; as cores de severidade continuam distinguíveis.


## Excluir agentes pelo painel administrativo

Entre com o token administrativo, abra Agentes e clique em Excluir na linha desejada. Confira o nome e o ID, digite o nome exato e confirme Excluir permanentemente. Cancelar preserva o cadastro. A operação remove definitivamente o agente e seus eventos, alertas, correlações, heartbeats e baselines do servidor, invalida sua credencial e registra a ação no log do servidor. Não desinstala o serviço nem remove a fila local do computador. Pare/desinstale o agente na máquina para encerrar a coleta. Para preservar o histórico, use desativação em vez de exclusão.

A requisição usada pelo painel exige autenticação administrativa no backend; credenciais individuais de agentes não têm essa permissão. A exclusão é transacional e usa o mesmo bloqueio por agente da ingestão. Não apague o agente principal se pretende continuar usando a identidade local armazenada pelo iniciador.

Para carregar a atualização: reinicie o servidor e atualize o navegador com Ctrl+F5. Em outra instalação, atualize o código preservando data, .env e configurações locais.


## Correção da instalação dos agentes Windows

INSTALAR_SERVICO.cmd agora usa um instalador Python, sem depender de scripts PowerShell ou mudar a ExecutionPolicy. Inclui diagnóstico, procura de Python global, reparo da mesma identidade e bloqueio de coletores duplicados. Para atualizar um pacote já enviado, siga [Correção dos agentes](CORRECAO_AGENTES.md). Preserve credentials.json, config.yaml, server-ca.pem e data; não gere outra identidade apenas para atualizar.

