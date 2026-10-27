# Agentes Windows: instalador corrigido

## Atualizar o computador que apresentou erro

1. Transfira `atualizar-agente-servico.zip` para a máquina monitorada.
2. Se houver um agente manual aberto, pare-o com Ctrl+C e espere encerrar.
3. Extraia a atualização **dentro da pasta do pacote individual correto**, onde já estão `credentials.json`, `config.yaml` e `server-ca.pem`. Substitua os arquivos do programa. A atualização não contém credenciais, configuração pessoal nem banco de dados.
4. Execute **DIAGNOSTICAR_AGENTE.cmd** como administrador. Ele mostra o ID do pacote e, quando houver, o ID instalado. IDs diferentes significam dois cadastros diferentes; não apague a fila e não edite as credenciais para tentar igualá-los.
5. Execute **INSTALAR_SERVICO.cmd como administrador**. O comando agora usa Python diretamente: não precisa alterar ExecutionPolicy, executar Unblock-File ou liberar scripts PowerShell.
6. É necessário Python 3.12+ instalado para todos os usuários em Program Files, com pip e Python Launcher. O instalador procura uma instalação global compatível. Na primeira execução, precisa de Internet para obter as dependências.
7. Aguarde **Running**. Confira também o heartbeat no dashboard: um serviço em execução não garante que o servidor recebeu logs.
8. Depois, reinicie a máquina e confira novamente o serviço e o heartbeat para validar a inicialização automática real.

Se o serviço já estiver instalado com o **mesmo ID**, o instalador permite reparar/atualizar o código, preservando a fila instalada. Se o ID for diferente, ele recusa a troca antes de alterar a instalação. Use o pacote correspondente ao ID instalado e envie ao administrador o resultado de DIAGNOSTICAR_AGENTE.cmd para decidir qual cadastro manter. Não exclua o cadastro instalado no painel enquanto quiser continuar recebendo essa identidade.

Para criar novos pacotes com a correção, atualize o projeto no servidor e use CRIAR_AGENTE.cmd normalmente. Os ZIPs já criados não são alterados automaticamente; aplique a atualização acima. Não recadastre máquinas só para atualizar o instalador.

## Controles

- STATUS_SERVICO.cmd: consulta o serviço e diagnóstico.
- PARAR_SERVICO.cmd: espera o serviço parar, preservando a fila.
- INICIAR_SERVICO.cmd: inicia e espera o estado Running.
- DESINSTALAR_SERVICO.cmd: para e remove o serviço, preservando configuração e fila.
- DIAGNOSTICAR_AGENTE.cmd: mostra runtime, IDs e estado; testa HTTPS se as dependências estiverem disponíveis. Não exibe tokens nem envia heartbeat fictício.

Todos os controles usam Python, não PowerShell. Execute-os como administrador. Não execute INICIAR_AGENTE.cmd ao mesmo tempo que o serviço: um bloqueio por máquina impede dois coletores simultâneos.

## O que foi corrigido

- Dependência do instalador em scripts PowerShell bloqueados por ExecutionPolicy.
- Pós-instalação do pywin32: a versão fixada inclui o script em Scripts; o módulo não foi encontrado no runtime testado. A chamada agora usa o caminho do script e abre um novo processo Python para carregar as dependências recém-instaladas.
- Descoberta de Python global, em vez de exigir um único caminho de versão.
- Reparo com a mesma identidade, recusa de troca por outro cadastro e preservação da fila na repetição da migração.
- Cópia de código com destinos explícitos, sem criar pastas agent/agent em reinstalações.
- Proteção contra coletores simultâneos, inclusive em duas pastas distintas.
- Limpeza da variável SIEM_STOP_FILE no agente remoto para evitar parada herdada de outro iniciador.
- Logs de rejeição HTTP informam códigos 401/403/422, sem tokens. 401 sugere credencial inválida/revogada; 403 pode indicar nome/identidade diferente do cadastro; 422 exige revisar os eventos/configuração.
- A criação do pacote agora verifica todos os arquivos antes de registrar a identidade, escreve em um ZIP temporário, valida seu conteúdo e só então publica o arquivo final. Se uma falha posterior ao cadastro ocorrer, remove apenas o novo cadastro incompleto.

## Erro de requirements-agent.txt ausente

Esse erro significa que a pasta do servidor foi alterada ou ficou incompleta. Não extraia `atualizar-agente-servico.zip` na raiz do servidor: ele deve ser extraído somente dentro de uma pasta individual de agente em uma máquina monitorada. Restaure `requirements-agent.txt` usando o projeto completo atualizado.

Se uma tentativa antiga deixou `NOME.zip` incompleto em `data\local-lab\enrollments`, renomeie esse arquivo para `NOME.incompleto.bak`. No painel administrativo, exclua o cadastro de mesmo nome que nunca ficou online. Depois execute CRIAR_AGENTE.cmd novamente. Um pacote completo existente deve ser reutilizado na máquina correspondente, não sobrescrito.

## Validação e limites

46 testes passaram, incluindo autorização de exclusão, normalização, fila, deduplicação, correlação, heartbeat, isolamento de identidades, pacote atômico e instalação/reparo com APIs do Windows simuladas. O bloqueio de instâncias foi testado com um mutex Windows real de nome exclusivo. Teste integrado local confirmou HTTPS, cadastro, lote, heartbeat, detecção e dashboard. Um aviso conhecido de depreciação Starlette/httpx permanece.

Nenhum serviço foi instalado ou alterado no sistema desta sessão. A instalação pelo Service Control Manager, permissões da máquina remota, firewall e execução após reinício precisam ser validados no computador monitorado. PostgreSQL/Docker e uma conexão física entre dois computadores não foram executados nesta revisão. Nenhum agente real ou evento real foi apagado.

Documentação oficial: https://github.com/mhammond/pywin32#running-as-a-windows-service
