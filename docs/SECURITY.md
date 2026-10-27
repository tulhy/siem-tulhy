# Modelo de segurança

## Fronteiras

1. **Endpoint:** sensores somente de leitura → outbox local. Usuários sem privilégios não devem poder alterar código, fila ou identidade do serviço. SYSTEM/administradores continuam tendo acesso; não se tenta esconder ou resistir ao administrador.
2. **Internet:** HTTPS autenticado e validado. HMAC cobre método, caminho, horário, nonce e hash dos bytes. TLS não é opcional no agente. Corpo comprimido é autenticado antes de ingestão e descomprimido com teto de memória no middleware.
3. **API:** token individual identifica e limita o agente. Agente não pode cadastrar outros, consultar telemetria ou enviar em nome de outra identidade/hostname. Administrador tem acesso total; proteja essa credencial como uma chave de administração.
4. **Persistência:** ACK após commit. Chave primária de evento global e conferência de hash detectam conflito de conteúdo. Nonces e contadores de rate limit ficam no banco. Lock por agente serializa ingestão, correlação e monitor.
5. **Dashboard:** consultas exigem Bearer; token só em memória. Renderização por `textContent`, sem interpolação de HTML de eventos. CSP bloqueia scripts externos/inline e frames; não há CDN.

## Ameaças mitigadas e limites

| Ameaça | Controle | Limite |
|---|---|---|
| Interceptação | TLS com CA confiável | Endpoint/CA comprometidos fora do controle |
| Adulteração/replay | HMAC, janela de relógio, nonce persistente | Credencial roubada permite forjar novos eventos |
| Duplicação por retry | `event_id` + hash do conteúdo | Sensores diferentes podem representar a mesma ação |
| Quebra de rede | SQLite durável + ACK explícito | Capacidade física e disponibilidade do disco |
| Falha na detecção | Estado pendente durável, worker e health | Erro lógico exige correção; não se marca evento como processado para esconder falha |
| Descompressão abusiva | Tetos comprimido/descomprimido | Defesa de DDoS requer controles na borda |
| Injeção em regra | DSL validada sem eval/regex arbitrária | Regras autorizadas ainda podem ser caras ou gerar ruído |
| XSS em evidência | DOM textual + CSP | Token administrador merece estação de análise protegida |
| Ausência de logs | Heartbeat e alertas de integridade | Agente malicioso pode simular um heartbeat saudável |

## Tratamento de dados

Campos com nomes de usuário, caminhos e IPs continuam sendo dados sensíveis, mesmo sem conteúdo de arquivos. Aplique acesso mínimo, finalidade, retenção definida e exclusão administrada. As regras e logs não imprimem credenciais; não ative logging HTTP de corpo/headers. Use criptografia de volume para filas, bancos e backups.

Tokens têm alta entropia; servidor armazena SHA-256 e compara em tempo constante. O Bearer chega somente por TLS e fornece a chave HMAC para aquela requisição. O hash armazenado sozinho não permite reproduzir a assinatura com o Bearer original. Rotação invalida a credencial anterior; atualize o agente por administração local segura e reinicie-o. Não existe canal remoto de atualização de segredos/comandos.

Não exponha Uvicorn sem TLS na Internet. O comando `--host 0.0.0.0 --port 8000` requer proxy/firewall; no Compose a porta fica privada. Credencial administrativa, credencial de banco e chaves de certificado nunca devem entrar no repositório.

## Incidente no próprio SIEM

Preserve filas e logs, registre o período sem cobertura e verifique relógio/CA/DNS/disco/permissões. Revogue agentes comprometidos, restaure o servidor de fonte confiável e investigue o conteúdo recebido sem presumir que veio de uma máquina íntegra. Não apague pendências para fazer um indicador voltar a verde. A ausência de alerta não prova ausência de ameaça.
