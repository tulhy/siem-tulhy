# Agentes em segundo plano

**Atualização:** o instalador CMD agora usa Python diretamente, sem ExecutionPolicy. Consulte [Correção dos agentes](CORRECAO_AGENTES.md) para atualizar pacotes antigos e diagnosticar identidades duplicadas.


Faça isto em **cada computador monitorado**, usando seu próprio pacote individual.

1. Instale Python 3.12+ para **todos os usuários**, em `C:\Program Files`, incluindo pip e Python Launcher. A instalação por usuário/venv usada pelo modo manual não serve como runtime do serviço LocalSystem.
2. Para pacotes antigos, extraia `atualizar-agente-servico.zip` na pasta que já contém `credentials.json`, `config.yaml` e `server-ca.pem`. Aceite substituir os scripts correspondentes. Essa atualização não contém credenciais nem altera a identidade da máquina. Pacotes novos já incluem os comandos.
3. Se `INICIAR_AGENTE.cmd` estiver rodando, pressione **Ctrl+C** e espere encerrar. Não mantenha dois agentes coletando simultaneamente.
4. Clique com o botão direito em **INSTALAR_SERVICO.cmd → Executar como administrador**. Confirme que o agente antigo foi parado. A primeira instalação precisa de Internet para instalar as dependências Python.
5. Aguarde o serviço **TulhyAgent** aparecer como **Running**. Feche a janela. O serviço continua após logout e inicia automaticamente quando o Windows ligar.
6. No dashboard do servidor, abra **Agentes** e confira o último heartbeat, normalmente em até 30 segundos.

Comandos disponíveis, executados como administrador:

| Arquivo | Ação |
| --- | --- |
| STATUS_SERVICO.cmd | Consulta o estado do serviço |
| PARAR_SERVICO.cmd | Para a coleta |
| INICIAR_SERVICO.cmd | Retoma a coleta |
| DESINSTALAR_SERVICO.cmd | Remove o serviço e preserva fila/configuração |

Também é possível usar `services.msc` e localizar **SIEM Tulhy Agent**. O serviço é visível e executa como LocalSystem. Se a política do PowerShell bloquear scripts, peça ao administrador a assinatura/liberação conforme a política da organização; os comandos não desativam essa proteção.

Arquivos do serviço: código em `C:\Program Files\Tulhy`, configuração/credenciais em `C:\ProgramData\Tulhy`, fila e `agent.log` no subdiretório `data`. A instalação restringe acesso a SYSTEM e Administradores. Na primeira instalação, copia a fila SQLite do agente manual com backup consistente, incluindo eventos pendentes e cursores. A fila original é preservada. Se já houver duas filas, a instalação recusa sobrescrever dados: reconcilie-as antes de reinstalar.

O servidor precisa estar ligado para receber. Enquanto estiver indisponível, o agente guarda eventos até o limite configurado e tenta reenviar. Computadores desligados ou suspensos não coletam durante esse período. Não execute `INICIAR_AGENTE.cmd` junto com o serviço.

Ao renovar a CA do laboratório, atualize também `C:\ProgramData\Tulhy\ca.pem` com o certificado público do servidor e reinicie o serviço. Ao mudar o IP central, atualize `server_url` em `C:\ProgramData\Tulhy\config.yaml`. Não copie a chave privada do servidor.

Validação desta atualização: 37 testes automatizados aprovados; sintaxe dos scripts PowerShell validada. A instalação real pelo Service Control Manager e o reinício das outras máquinas ainda devem ser verificados nelas; não foram realizados automaticamente nesta sessão.
