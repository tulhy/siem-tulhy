# Validação da entrega

Data: 24/09/2026. Ambiente: Windows, Python 3.12.14, ambiente virtual isolado. Bibliotecas principais fixadas nos arquivos requirements.

## Executado

| Verificação | Resultado |
|---|---|
| `python -m pytest -q` | **34 testes aprovados**, última execução em aproximadamente 12 segundos |
| `python -m compileall -q agent server shared scripts` | Aprovado |
| `node --check dashboard/static/app.js` | Aprovado |
| Parser PowerShell em `scripts/windows-agent.ps1` | Sem erros sintáticos |
| HTTPS real em Uvicorn com CA temporária | Envio, perda de ACK, retransmissão e deduplicação aprovados |
| Certificado não confiável | Conexão rejeitada como esperado; sem desativar TLS |
| Worker de detecção em segundo plano | Evento persistido convertido em alerta |
| SQLite concorrente | Dois POSTs com o mesmo ID armazenam um único evento |
| Fila concorrente | Quatro produtores, sem perda na capacidade testada |
| Falha de detecção simulada | Rollback preserva pendência; nova engine processa depois |
| Coletores reais Windows, leitura única | 303 processos, 104 conexões e 213 mudanças/fotografia de serviços observadas; contagens são de um instante do ambiente de teste |
| Degradação de coleta | Quatro eventos de integridade: visibilidade parcial, indisponibilidade de serviços e dois canais inacessíveis |
| Dashboard no navegador | Login de laboratório, indicadores, agentes/eventos/alertas e detalhe de correlação inspecionados |
| Dados para QA visual | 3 identidades e 204 eventos exclusivamente sintéticos em banco temporário separado |
| Erros de console do navegador | Nenhum erro registrado na verificação final |
| YAML Compose e modelo PostgreSQL | Leitura do Compose, isolamento de portas e compilação do DDL para PostgreSQL aprovados |

Os metadados reais do smoke test Windows não foram enviados à nuvem nem incluídos no pacote. A inspeção visual e os testes HTTP usaram somente dados sintéticos. Nenhum serviço Windows foi instalado nesta máquina e nenhuma política de segurança/auditoria foi alterada.

Há **um aviso de depreciação** do Starlette TestClient sobre seu adaptador httpx. Não é falha da aplicação e não foi ocultado. A migração futura do adaptador de testes deve ser avaliada ao atualizar dependências.

## Ainda precisa de homologação no destino

- Build e execução do Docker Compose: Docker não estava disponível neste ambiente.
- Integração com uma instância PostgreSQL real: o dialeto/DDL foi validado, mas os testes de banco rodaram em SQLite.
- Instalação, reboot, recovery e desinstalação do serviço no Service Control Manager com Python global e privilégios administrativos. O contrato de parada e a sintaxe do instalador foram testados.
- Canais Windows Security/PowerShell/Sysmon habilitados com eventos reais de todas as categorias e permissões de produção.
- Caddy/ACME com DNS público, firewall, certificado público, domínio real e políticas de proxy.
- Testes prolongados de carga, esgotamento físico de disco, desligamento abrupto do sistema, retenção e restauração de backup.

Não se atribui garantia de detecção total, taxa de EPS certificada ou resistência a comprometimento de administrador local a este projeto.

## Progressão das fases

1. Schema/normalização: 2 testes.
2. Coletores: 5 testes.
3. Outbox: 7 testes.
4. Transporte: 10 testes.
5. API/banco: 14 testes.
6. Regras/evidências: 16 testes.
7. Correlação/baseline/risco: 19 testes.
8. Heartbeat/worker: 21 testes.
9. Dashboard: 22 testes e sintaxe JavaScript.
10. Serviço: 23 testes e parser PowerShell.
11. Segurança/HTTPS/cobertura: 29 testes, depois ampliados com confiabilidade concorrente.
12. Empacotamento/documentação: suíte final de 34 testes e validações estáticas de implantação.

Uma correção relevante feita durante a validação separou `processed_at` de `detection_status`: ser usado como evidência por outra regra não pode retirar um evento da fila de análise de suas próprias regras. Também foram acrescentados agrupamento Sysmon por ProcessGuid, regra de falhas distribuídas entre usuários e contadores O(1) de ocupação da outbox.

## Iniciador local acrescentado após a entrega inicial

`scripts/local_lab.py --check` foi executado com dados em diretório temporário separado e portas 18080/18443. Resultado: **CHECK OK** para HTTPS, cadastro, lote, heartbeat, detecção e dashboard HTTP, com encerramento dos processos filhos. O iniciador usa o SID real do processo para proteger seus arquivos, inclusive quando o nome de usuário nas variáveis de ambiente difere da identidade efetiva do Windows. O caminho de execução contínua usa o agente já implementado; o teste do iniciador não instalou serviço nem coletou telemetria real.

## Pacotes para rede local

Foram acrescentados modo de escuta em IPv4 privado específico, certificado com IP no SAN e empacotador individual para outro computador. O teste adicional verifica endereço/identidade do pacote, presença do certificado público, integridade do ZIP e ausência da chave privada, token administrativo e código do servidor. A conexão entre dois computadores físicos e a regra de firewall não foram exercitadas nem alteradas automaticamente nesta máquina. A primeira tentativa da suíte encontrou permissões antigas na pasta temporária do pytest; a repetição usa pasta de teste própria na workspace e desabilita apenas o cache de testes.

## Servidor em segundo plano

O controlador foi exercitado no Windows com `start --check`, em pasta separada e portas 18081/18444: HTTPS, cadastro e detecção sintética concluídos, processo permaneceu ativo após o comando inicial retornar, `status` identificou execução, segunda chamada `start` não duplicou a instância, `stop` encerrou os componentes e `status` confirmou parado. O teste não coletou dados reais nem instalou serviço. O stop usa um arquivo local protegido, sem endpoint de controle remoto. PID, instante de criação e linha de comando são conferidos para não confundir reutilização de PID. Este modo não configura início automático após reboot.

Atualização OR2/serviço: 37 testes aprovados, incluindo preservação da fila SQLite com WAL/cursores e recusa de sobrescrita. Scripts PowerShell analisados sem erros de sintaxe. Logo e paleta conferidas no navegador. Instalação do serviço em máquinas reais não executada nesta sessão.


Exclusão administrativa: 40 testes aprovados (um aviso de depreciação Starlette/httpx). Verificados autenticação administrativa, rejeição de token de agente, confirmação de nome, exclusão de dependências, isolamento de IDs mesmo com nomes iguais, invalidação da credencial e rollback em falha. JavaScript passou em node --check. No navegador, conferidos botão Excluir, confirmação bloqueada até digitar o nome exato e cancelamento. Nenhum agente real foi excluído.


Revisão dos agentes: 46 testes passaram e o teste integrado local HTTPS foi aprovado. Instalação/reparo validados com APIs do Windows simuladas; mutex real testado com nome isolado. A geração atômica foi validada com ausência de fonte e com um pacote sintético completo. A instalação real na outra máquina e o reboot permanecem pendentes. Detalhes em CORRECAO_AGENTES.md.

