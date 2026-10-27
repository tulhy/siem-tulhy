# Conectar outro computador ao SIEM deste computador

Este procedimento pressupõe dois computadores na mesma rede local confiável (Wi-Fi/Ethernet), sem isolamento de clientes. O computador que recebe os logs precisa permanecer ligado, com o servidor aberto.

## No computador servidor

1. Se `INICIAR_LOCAL.cmd` estiver aberto, pare-o com **Ctrl+C**.
2. Abra **INICIAR_REDE.cmd** (ou, em segundo plano, **INICIAR_SEGUNDO_PLANO.cmd** depois da primeira vez). Não é preciso informar IP: a API recebe via HTTPS na porta **8443** em **todas** as conexões do computador, cabo e Wi-Fi ao mesmo tempo. O dashboard HTTP continua restrito a este computador em **http://127.0.0.1:8000**.
3. O certificado é emitido por uma autoridade própria do SIEM (`data/local-lab/tls/tulhy-ca.pem`, válida por 10 anos). Ele cobre o nome do computador e os IPs atuais e é reemitido sozinho quando um IP novo aparece ou quando faltam 30 dias para vencer; os agentes continuam confiando sem nenhuma troca de arquivo. A chave `tulhy-ca-key.pem` nunca sai do servidor.
4. Clique com o botão direito em **CRIAR_REGRA_FIREWALL.cmd** → **Executar como administrador**. Ele cria a regra "SIEM Tulhy - rede local": porta 8443, somente origens da sub-rede local, somente perfil **Particular**. Deixe o cabo e o Wi-Fi do servidor como rede Particular; em rede Pública a regra não vale. Não desative o firewall e não redirecione essa porta no roteador para a Internet.

5. Execute **CRIAR_AGENTE.cmd**. Digite um nome para identificar o outro computador, por exemplo `PC-ESCRITORIO`. Não precisa ser o hostname real: o pacote usa esse nome consistentemente no cadastro e na configuração.
6. O caminho do ZIP aparecerá na tela: `data/local-lab/enrollments/PC-ESCRITORIO.zip` dentro do projeto. O pacote contém uma credencial exclusiva; transfira-o por um meio privado, como pendrive ou compartilhamento protegido.

## No outro computador

1. Instale Python **3.12+**, incluindo o **Python Launcher** (`py`).
2. Extraia **todo** o ZIP individual em uma pasta privada, dentro da sua conta de usuário. Não execute diretamente de dentro do ZIP e não use uma pasta compartilhada publicamente.
3. Para funcionar sem terminal, siga [Agente em segundo plano](AGENTE_SEGUNDO_PLANO.md): instale Python para todos os usuários e execute **INSTALAR_SERVICO.cmd** como administrador.
4. Após confirmar o serviço **Running**, pode fechar a janela. O primeiro heartbeat deve chegar em alguns segundos; espere até cerca de 30 segundos para conferir o dashboard. Sem conexão, a fila é preservada localmente e o agente tenta novamente.

## Como conferir

No servidor, abra **http://127.0.0.1:8000**, use o token administrativo local e entre em **Agentes**. O nome escolhido deve aparecer online; em **Eventos**, filtre por esse nome.

Se estiver offline, no computador do agente teste a porta (substitua pelo IP verdadeiro):

```powershell
Test-NetConnection 192.168.1.10 -Port 8443
```

`TcpTestSucceeded: True` confirma somente conectividade TCP, não autenticação completa. Verifique também o servidor aberto, o nome/IP do servidor, o perfil/regra do firewall, isolamento de clientes no Wi-Fi, relógio do Windows e o log `data/agent.log` dentro do pacote extraído. Não remova a verificação do certificado para contornar erro de TLS.

## Mais computadores e reinício

- Execute **CRIAR_AGENTE.cmd** uma vez por novo computador, com nome diferente. Transfira apenas o ZIP correspondente. Não reutilize identidade/fila em várias máquinas.
- O serviço do agente inicia automaticamente com o Windows; use PARAR_SERVICO.cmd e INICIAR_SERVICO.cmd para controlá-lo. O modo manual continua usando Ctrl+C.
- Os agentes procuram o servidor pelo **nome do computador** (que acompanha o IP atual) e, se não responder, pelos IPs conhecidos. Assim funcionam com o servidor no cabo, no Wi-Fi ou nos dois. Reservar o IP no roteador continua sendo recomendável, mas não é obrigatório.
- Agentes instalados antes desta versão: gere **CRIAR_ATUALIZACAO_AGENTES.cmd** no servidor, execute `ATUALIZAR_AGENTE.cmd` (como administrador) em cada máquina e só então reinicie o servidor. Cadastro e fila são preservados.
- Nunca copie `admin-token.txt`, `server.db`, `localhost-key.pem` ou `tulhy-ca-key.pem` para as máquinas monitoradas. O empacotador não inclui esses arquivos.
- Para remover a regra de firewall criada por este guia: `netsh advfirewall firewall delete rule name="SIEM Tulhy - rede local"` em um prompt administrativo.
- Computadores em redes diferentes precisam de uma implantação própria para isso, como VPN ou servidor central HTTPS. Este guia não configura acesso pela Internet.
