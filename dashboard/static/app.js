'use strict';
// Presentation only: original rule IDs, evidence and API values stay unchanged.
const ruleHelp = {
 DEFENDER_REALTIME_OFF:['Proteção em tempo real está inativa no Defender','A consulta de estado informou que essa proteção estava inativa. Pode existir outro antivírus ativo ou o Defender estar em modo passivo.','Confira o antivírus usado pela empresa e o modo de funcionamento informado.'],
 DEFENDER_SIGNATURES_OLD:['Definições do Defender estão desatualizadas','As definições consultadas tinham sete dias ou mais. Isso reduz a cobertura se o Defender for o antivírus ativo.','Verifique a atualização das definições e a conectividade com o serviço de atualização.'],
 DEFENDER_THREAT:['Defender detectou uma ameaça ou programa indesejado','A política da organização dá prioridade crítica a detecções do antivírus. Isso inclui ameaças como trojans, backdoors, ransomware e keyloggers quando identificados pelo Defender. Confira o nome e o estado informado; uma detecção não confirma remoção.','Abra o histórico de proteção do Defender nessa máquina, confira o estado atual e encaminhe a detecção ao responsável de segurança.'],
 DEFENDER_ACTION_FAILED:['Defender não conseguiu tratar uma ameaça','O antivírus registrou falha ao executar uma ação de proteção. A classificação crítica pede investigação urgente.','Siga o procedimento de resposta a incidentes e confira o erro no Defender. Se houver sinais de acesso indevido ativo, isole a máquina conforme a política da empresa.'],
 DEFENDER_ACTION:['Defender registrou uma ação sobre uma ameaça','A ação pode ser quarentena, remoção, bloqueio ou até permissão. Leia o campo Ação do antivírus; este alerta não declara a máquina limpa.','Confira o resultado no histórico de proteção. Uma ação posterior não resolve automaticamente o alerta anterior.'],
 DEFENDER_DISABLED:['Uma proteção do antivírus foi desativada','O Defender registrou a desativação de um componente. Pode ser uma mudança autorizada ou uso de outro antivírus.','Confirme com o suporte qual proteção está ativa nessa máquina.'],
 DEFENDER_CONFIGURATION:['Configuração do antivírus mudou','Foi registrada uma mudança no Defender. Atualizações e administração legítima também podem causar isso.','Confira se a mudança era esperada. Isso não prova desativação da proteção.'],
 SYSMON_REMOTE_THREAD:['Um programa iniciou execução dentro de outro','O Sysmon registrou a criação de uma thread em outro processo. É um sinal possível de injeção de código, mas também ocorre em ferramentas legítimas.','Confira o programa de origem e o processo de destino nas atividades abaixo.'],
 SYSMON_PROCESS_TAMPERING:['Sysmon observou manipulação de um processo','O monitor do Windows registrou alteração da imagem de um processo. A regra atribui prioridade crítica a esse comportamento.','Investigue o programa e os demais eventos no mesmo horário com a equipe de segurança.'],
 PROCESS_PERSISTENCE_NETWORK:['Programa iniciou, configurou início automático e acessou a rede','O mesmo PID e instante de criação ligaram três comportamentos em até cinco minutos. Essa combinação exige revisão urgente, embora possa ocorrer em instalações autorizadas.','Confira o programa, a mudança e os destinos. A prioridade crítica vem da combinação, não apenas da conexão.'],
 SYSMON_PERSISTENCE_NETWORK:['Sysmon ligou execução, início automático e rede','O identificador de processo do Sysmon relacionou os três comportamentos em até cinco minutos.','Confira se houve instalação autorizada; investigue o arquivo e o destino se a atividade não for reconhecida.'],
 TEMP_EXECUTION:['Programa aberto em uma pasta temporária ou de downloads','Um programa foi iniciado em uma pasta usada para arquivos temporários ou downloads. Instaladores legítimos também fazem isso.','Confira o nome, o caminho e se a pessoa esperava abrir esse programa.'],
 FILE_CHANGE:['Arquivo acompanhado pelo sistema foi alterado','Um arquivo em uma pasta monitorada foi criado, modificado, excluído ou movido. Isso pode ser uma edição normal.','Confira o caminho e o horário e confirme se a alteração era esperada.'],
 PERSISTENCE_CHANGE:['Configuração de início automático foi alterada','Foi observada uma mudança que pode permitir que um programa inicie automaticamente. Instalações e atualizações autorizadas também podem causar isso.','Peça ao responsável de TI para conferir o serviço, a tarefa ou a configuração alterada.'],
 POWERSHELL_SIGNAL:['Comando do Windows precisa de revisão','O PowerShell, ferramenta usada para automatizar tarefas, registrou sinais que merecem análise. Administradores também usam esses recursos de forma legítima.','Confira quem executou a tarefa e se ela fazia parte de uma manutenção autorizada.'],
 TELEMETRY_INTEGRITY:['Parte do monitoramento está com falha','O agente informou uma limitação na coleta: pode faltar permissão, haver perda de registros ou um componente estar indisponível. A visibilidade dessa máquina pode estar reduzida.','Confira os registros do agente e peça ao suporte para verificar permissões e componentes de coleta.'],
 RESOURCE_ANOMALY:['Uso de recursos acima do limite configurado','CPU, memória ou disco ultrapassou o limite definido para o monitoramento. Isso também acontece com programas pesados e pouco espaço livre.','Confira qual recurso está sobrecarregado e os programas em execução.'],
 KNOWN_TEST_HASH:['Arquivo corresponde a um indicador de teste','A assinatura digital de conteúdo (hash) corresponde ao indicador de laboratório desta regra. Isso não confirma uma infecção.','Verifique se alguém está realizando um teste autorizado.'],
 AUTH_FAILURE_BURST:['Várias tentativas de acesso falharam para a mesma conta','O sistema reuniu falhas de acesso para o mesmo usuário em pouco tempo. Pode ser senha incorreta, configuração antiga ou tentativa de acesso indevido.','Confirme com a pessoa se ela tentou entrar e verifique a origem das tentativas.'],
 AUTH_FAILURE_MACHINE_BURST:['Várias tentativas de acesso falharam nesta máquina','Foram reunidas falhas de acesso neste computador, possivelmente envolvendo contas diferentes ou usuários não identificados.','Confira as contas envolvidas, os horários e a origem das tentativas.'],
 CONNECTION_BURST:['Um programa fez muitas conexões em pouco tempo','O mesmo programa registrou várias conexões de rede em um intervalo curto. Navegadores, atualizações e ferramentas de teste também podem fazer isso. Não significa necessariamente uma varredura de portas.','Confira o programa, os destinos e se a atividade era esperada.'],
 TEMP_THEN_NETWORK:['Programa em pasta temporária se conectou à rede','Um programa iniciou em uma pasta temporária e, em seguida, fez uma conexão de rede. Instaladores e atualizações também podem apresentar essa sequência.','Confira a origem do programa e para qual endereço ele se conectou.'],
 SYSMON_TEMP_THEN_NETWORK:['Programa em pasta temporária se conectou à rede (Sysmon)','Os registros do Sysmon, componente de monitoramento do Windows, ligaram a abertura do programa à conexão de rede do mesmo programa.','Confira o arquivo executado, seu usuário e o destino da conexão.'],
 PROCESS_THEN_PERSISTENCE:['Programa iniciou e alterou uma configuração de início automático','O sistema relacionou a abertura de um programa a uma mudança que pode fazê-lo executar automaticamente no futuro.','Confirme se houve uma instalação autorizada e revise a configuração alterada.'],
 NEW_NETWORK_DESTINATION:['Programa acessou um destino ainda não visto no histórico','Depois do período inicial de observação, foi encontrada uma combinação de programa e destino diferente das já registradas nesta máquina. Novo não significa perigoso.','Confira se o destino pertence a um serviço usado pela empresa ou a uma atualização esperada.'],
 TELEMETRY_LOST:['Computador deixou de enviar sinais de funcionamento','O servidor ficou sem receber a confirmação periódica de funcionamento dentro do prazo configurado. A máquina pode estar desligada, suspensa, sem rede ou com o agente parado.','Confira se a máquina está ligada, conectada e com o serviço TulhyAgent em execução.'],
 TULHY_TEST_CRITICAL:['SIMULAÇÃO: teste de alerta crítico','A regra de laboratório reconheceu o programa benigno de teste. A classificação crítica serve para validar o painel e não indica uma invasão.','Confirme quem iniciou o teste e marque o alerta como resolvido após a validação.']
};
Object.assign(ruleHelp,{
 EXPOSED_SENSITIVE_PORT:['Uma porta sensível está disponível nesta máquina','O agente observou uma porta da lista de atenção alta em escuta (TCP) ou vinculada a um programa (UDP). Isso indica um serviço local; a acessibilidade pela Internet depende da rede e do firewall.','Confira a porta local, o programa responsável e se esse serviço deve ficar disponível.'],
 INBOUND_64668:['Conexão de entrada na porta 64668','O computador recebeu uma conexão na porta local 64668. Pela política configurada, essa atividade recebe prioridade média.','Confira a origem remota e o programa que recebeu a conexão.'],
 POLICY_SCRIPT_HTML:['Arquivo .vbs ou .htm observado na máquina','A política da organização classifica a presença dessas extensões como crítica para revisão. Scripts e páginas HTML também podem ser legítimos; a extensão sozinha não comprova malware.','Confira o caminho, a origem e se o arquivo foi autorizado. Encaminhe o arquivo ao processo de análise da empresa.'],
 REMOTE_EXECUTION_SUSPECT:['Conexão remota ligada a execução suspeita','Foram combinados sinais de execução e comunicação do mesmo processo. Esse conjunto recebe prioridade crítica por possível acesso remoto indevido; conexões remotas legítimas também precisam ser consideradas.','Confira os eventos relacionados, o programa, o usuário e a origem remota. Compare com as ferramentas de suporte autorizadas.'],
 INBOUND_PORT_SCAN:['Uma origem tentou acessar várias portas','O monitor reuniu acessos de entrada a portas locais diferentes em um intervalo curto. Esse padrão pode indicar varredura de portas ou uma ferramenta de inventário autorizada.','Confira o endereço de origem, as portas locais e a janela descrita na evidência.'],
 INBOUND_FLOOD:['Muitas conexões de entrada da mesma origem','O volume de registros de entrada ultrapassou o limite configurado e recebeu prioridade crítica por possível sobrecarga ou tentativa de negação de serviço. Picos legítimos também podem atingir o limite.','Confira o volume, a origem e o impacto no serviço. Use os registros de rede e de firewall para investigar.'],
 DISTRIBUTED_INBOUND_FLOOD:['Grande volume de entrada de várias origens','O monitor reuniu muitas conexões de entrada de múltiplos endereços em pouco tempo. O padrão recebe prioridade crítica por possível negação de serviço distribuída; requer confirmação do impacto e do tráfego.','Confira as origens, o volume e a disponibilidade do serviço com a equipe responsável pela rede.'],
 SUSPICIOUS_DOMAIN:['Consulta a domínio da lista de atenção','Foi observada uma consulta DNS para um domínio configurado como suspeito. A prioridade é média. Uma consulta DNS pode ser feita por um programa em segundo plano e não comprova que a pessoa abriu o site.','Confira o domínio, o programa e a origem do indicador antes de concluir que houve acesso a conteúdo malicioso.']
});
ruleHelp.POLICY_SCRIPT_HTML_MOVED=ruleHelp.POLICY_SCRIPT_HTML;
const displayLabels = {LOW:'Baixa',MEDIUM:'Média',HIGH:'Alta',CRITICAL:'Crítica',online:'Online',offline:'Offline',active:'Em aberto',resolved:'Resolvido',pending:'Aguardando análise',matched:'Regra acionada',clear:'Nenhuma regra acionada'};
const eventLabels = {'process.start':'Programa iniciado','process.stop':'Programa encerrado','network.connection':'Conexão de rede observada','file.created':'Arquivo criado','file.modified':'Arquivo alterado','file.deleted':'Arquivo excluído','file.moved':'Arquivo movido','auth.failure':'Tentativa de acesso malsucedida','auth.success':'Acesso realizado','persistence.change':'Início automático alterado','powershell.observed':'Atividade do PowerShell','resource.anomaly':'Uso de recursos acima do limite','telemetry.integrity':'Limitação na coleta de informações','telemetry.started':'Agente iniciado','service.started':'Serviço iniciado','service.stopped':'Serviço parado'};
Object.assign(eventLabels,{'antivirus.detected':'Detecção do antivírus','antivirus.action':'Ação informada pelo antivírus','antivirus.remediation_failed':'Falha ao tratar ameaça','antivirus.protection_disabled':'Proteção do antivírus desativada','antivirus.configuration_changed':'Configuração do antivírus alterada','process.remote_thread':'Execução em outro processo','process.tampering':'Manipulação de processo','file.access':'Acesso a objeto auditado pelo Windows','service.change':'Estado de serviço alterado'});
Object.assign(eventLabels,{'file.present':'Arquivo encontrado no inventário','network.listen':'Porta TCP em escuta','network.bind':'Porta UDP vinculada','network.dns':'Consulta DNS observada','network.blocked':'Tentativa de conexão bloqueada'});
displayLabels.disabled='Coleta desativada';
function eventFacts(e){
 const facts=element('dl',undefined,'event-facts');
 const add=(label,value)=>{if(value!==undefined&&value!==null&&value!==''){facts.append(element('dt',label),element('dd',String(value)));}};
 add('Horário observado',formatTime(e.timestamp));add('Recebido pelo servidor',e.received_at?formatTime(e.received_at):null);
 add('Máquina',e.hostname);add('Usuário',e.user);add('Origem do registro',e.source);
 add('Nível de atenção no painel',displayLabels[e.severity]||e.severity);add('Classificação recebida do agente',displayLabels[e.reported_severity]||e.reported_severity);add('Motivo da classificação',e.severity_reason);
 add('Programa',e.process?.name);add('Caminho do programa',e.process?.path);add('PID (número do processo)',e.process?.pid);add('Identificador do arquivo (SHA-256)',e.process?.sha256||e.file?.sha256);
 add('Endereço local (máquina monitorada)',e.network?.local_ip);add('Porta local',e.network?.local_port);add('Endereço remoto',e.network?.remote_ip);add('Porta remota',e.network?.remote_port);add('Protocolo',e.network?.protocol);add('Arquivo ou objeto',e.file?.path);add('Novo caminho do arquivo',e.file?.destination);
 const direction=e.raw_event?.direction;add('Sentido da conexão',({inbound:'Entrada: outro computador iniciou a conexão',outbound:'Saída: esta máquina iniciou a conexão',unknown:'Não determinado pela fonte'})[direction]||direction);add('Origem da identificação do sentido',e.raw_event?.direction_source);add('Domínio consultado (DNS)',e.raw_event?.domain);
 const labels={threat_name:'Nome informado pelo antivírus',threat_category:'Categoria informada pelo antivírus',vendor_severity:'Gravidade informada pelo antivírus',action:'Ação do antivírus',error_code:'Código de erro',affected_resource:'Recurso afetado',target_image:'Processo de destino',target_pid:'PID de destino',reason:'Motivo técnico da limitação',channel:'Log de origem',event_code:'Código do evento Windows',key:'Configuração de início automático',resource:'Recurso sobrecarregado',percent:'Uso (%)',access_mask:'Código de acesso do Windows',object_type:'Tipo de objeto auditado'};
 for(const [key,label] of Object.entries(labels))add(label,e.raw_event?.[key]);
 const status=e.raw_event||{};if(e.event_type==='antivirus.status'){add('Proteção em tempo real',status.realtime_enabled===true?'Ativa':status.realtime_enabled===false?'Inativa':'Não informada');add('Antivírus habilitado',status.antivirus_enabled===true?'Sim':status.antivirus_enabled===false?'Não':'Não informado');add('Idade das definições (dias)',status.signatures_age_days);add('Modo do Defender',status.running_mode);}
 return facts;
}
function eventDetail(e){const body=showDetail(eventLabels[e.event_type]||e.event_type);body.append(element('p','Registro observado pelo agente. Campos ausentes não foram informados pela fonte; o registro sozinho não confirma uma invasão.'),eventFacts(e));technicalSection(body,'Ver dados técnicos e classificação recebida',e);}
eventLabels['antivirus.status']='Estado consultado do Defender';
async function protectionDetail(agent){try{const data=await api('agents/'+encodeURIComponent(agent.id)+'/protection');const body=showDetail('Cobertura de proteção: '+agent.hostname);body.append(element('p','Versão do agente: '+data.version),element('p','Online confirma comunicação, não ausência de vírus. Este painel consulta o Defender; não substitui o antivírus/EDR.'),element('p',data.collection_enabled?'Coleta habilitada.':'Coleta desativada pelo administrador; histórico preservado.'));if(!data.status){body.append(element('p','Ainda não há consulta de estado do Defender. Atualize o agente para 1.1.0, confira a opção windows_events e as permissões do serviço. Se o Defender não estiver disponível, verifique qual antivírus é usado.'));}else{body.append(element('p',data.stale?'Informação antiga: não use esse estado para concluir a proteção atual.':'Consulta recente de estado recebida.'),eventFacts({event_type:'antivirus.status',timestamp:data.observed_at,hostname:agent.hostname,source:'defender.status',raw_event:data.status}));}body.append(element('p','Câmera: não há confirmação universal de acesso. Arquivos: a coleta de acessos depende de auditoria de objetos configurada no Windows. Sysmon: os sinais adicionais dependem da instalação e configuração desse componente.'));}catch(err){notice(err.message);}}
function helpFor(a){const h=ruleHelp[a.rule_id];return h?{title:h[0],description:h[1],action:h[2]}:{title:a.title||a.rule_id,description:a.description||'Esta regra não possui uma explicação adicional cadastrada.',action:'Consulte os eventos e a descrição original com o responsável de TI.'};}
function technicalSection(body,title,data){const d=element('details');d.append(element('summary',title),element('pre',typeof data==='string'?data:JSON.stringify(data,null,2)));body.append(d);}
function explainEvidence(a){
 const ev=a.evidence||{},parts=[];
 if(Array.isArray(a.events)&&a.events.length)parts.push(`${a.events.length} registro(s) estão ligados a este alerta.`);
 if(ev.threshold>1)parts.push(`A regra exige pelo menos ${ev.threshold} registros que atendam às condições.`);
 if(ev.window_seconds)parts.push(`O intervalo considerado pela regra é de até ${ev.window_seconds} segundos.`);
 if(ev.event_time_start&&ev.event_time_end)parts.push(`Atividade observada entre ${formatTime(ev.event_time_start)} e ${formatTime(ev.event_time_end)}.`);
 return parts.join(' ')||a.reason||'Consulte os detalhes originais para conferir o motivo registrado pelo servidor.';
}
function occurrenceText(a){
 if(a.severity!=='CRITICAL'||a.occurrence_scope!=='same_rule_and_agent'||!Number.isInteger(a.occurrence_count)||a.occurrence_count<1)return '';
 const repeats=Math.max(0,a.occurrence_count-1),hours=(a.occurrence_window_seconds||86400)/3600;
 return `${a.occurrence_count} ocorrência(s) · ${repeats} repetição(ões) da mesma regra nesta máquina nas ${hours} horas até este alerta.`;
}
let token = '', busy = false;
const $ = id => document.getElementById(id);
const pages = ['overview','agents','events','alerts','exclusions'];
const offsets = {agents:0,events:0,alerts:0};
const names = {overview:'Visão geral',agents:'Agentes',events:'Eventos',alerts:'Alertas',exclusions:'Exclusões'};
const formatTime = value => value ? new Date(typeof value==='number'?value*1000:value).toLocaleString('pt-BR') : 'Aguardando';
function updateClock(){const clock=$('clock');if(clock){const now=new Date();clock.textContent=now.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});clock.dateTime=now.toISOString();}}
const element = (tag,text,className) => { const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(className)e.className=className; return e; };
function notice(text){$('notice').textContent=text;$('notice').hidden=!text;}
async function api(path,options={}){
  const r=await fetch('/api/v1/'+path,{...options,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json',...(options.headers||{})}});
  if(!r.ok){let detail='';if(r.status===429){try{detail=String((await r.json()).detail||'');}catch(e){}}const messages={401:'A chave de acesso não foi aceita. Entre novamente com o token administrativo do servidor.',403:'Seu acesso não permite esta ação.',404:'Este registro não foi encontrado. Atualize a página; ele pode ter sido removido.',422:'Algum dado ou filtro não foi aceito. Confira os campos preenchidos.',429:'Há muitas solicitações neste momento. Aguarde alguns segundos e tente novamente.'};const error=new Error(detail||messages[r.status]||`O servidor não conseguiu concluir a solicitação (código ${r.status}). Tente novamente; se continuar, avise o suporte.`);error.status=r.status;throw error;}
  return r.json();
}
function page(){return pages.includes(location.hash.slice(1))?location.hash.slice(1):'overview';}
function badge(value){return element('span',displayLabels[value]||value,'badge '+value);}
function cell(row,value){const c=document.createElement('td');c.append(value instanceof Node?value:document.createTextNode(value??'—'));row.append(c);}
function empty(body,columns){const row=element('tr');const td=element('td','Nenhum registro neste período.','empty');td.colSpan=columns;row.append(td);body.append(row);}
function filters(form){const p=new URLSearchParams();for(const [key,value] of new FormData($(form))){if(value)p.set(key,['start','end'].includes(key)?new Date(value).toISOString():value);}return p;}
function pager(p,count){$(p+'-page').textContent=`Página ${offsets[p]/100+1} · ${count} registros`;document.querySelectorAll(`[data-page="${p}"]`).forEach(b=>b.disabled=Number(b.dataset.delta)<0?offsets[p]===0:count<100);}
function bars(id,items){const box=$(id);box.replaceChildren();if(!items.length){box.append(element('p','Sem dados no período.','empty'));return;}const max=Math.max(...items.map(x=>x.value),1);for(const item of items.slice(0,7)){const row=element('div'),line=element('div',undefined,'bar-line');line.append(element('span',item.name),element('strong',item.value.toLocaleString('pt-BR')));const meter=element('progress');meter.max=max;meter.value=item.value;meter.setAttribute('aria-label',item.name+': '+item.value);row.append(line,meter);box.append(row);}}
function canvas(id){const c=$(id),dpr=devicePixelRatio||1;const w=c.clientWidth,h=175;c.width=w*dpr;c.height=h*dpr;const x=c.getContext('2d');x.scale(dpr,dpr);return {x,w,h};}
function timeline(data){const {x,w,h}=canvas('timeline');x.strokeStyle='#294638';x.fillStyle='#a1b6a8';x.font='10px Segoe UI';for(let i=0;i<4;i++){const y=15+i*40;x.beginPath();x.moveTo(0,y);x.lineTo(w,y);x.stroke();}const max=Math.max(1,...data.map(i=>i.value));const step=w/24;x.fillStyle='#ffc21a';data.forEach((v,i)=>x.fillRect(i*step+2,145-120*v.value/max,Math.max(2,step-5),Math.max(2,120*v.value/max)));x.fillStyle='#a1b6a8';['-24h','-18h','-12h','-6h','agora'].forEach((v,i)=>x.fillText(v,i*(w-32)/4,170));$('timeline').setAttribute('aria-label',data.map(d=>d.name+': '+d.value).join(', '));}
function severity(data){const {x,w}=canvas('severity');const total=data.reduce((a,b)=>a+b.value,0);const colors={LOW:'#79dda0',MEDIUM:'#ffc21a',HIGH:'#efa664',CRITICAL:'#f57190'};let angle=-Math.PI/2;const cx=Math.min(70,w*.23),cy=77;x.lineWidth=17;x.strokeStyle='#294638';x.beginPath();x.arc(cx,cy,48,0,Math.PI*2);x.stroke();for(const item of data){const end=angle+(total?item.value/total:0)*Math.PI*2;x.strokeStyle=colors[item.name]||'#8ba4c0';x.beginPath();x.arc(cx,cy,48,angle,end);x.stroke();angle=end;}x.fillStyle='#edf4ed';x.textAlign='center';x.font='23px Segoe UI';x.fillText(total.toLocaleString('pt-BR'),cx,85);x.textAlign='left';Object.keys(colors).forEach((name,i)=>{const y=30+i*31;x.fillStyle=colors[name];x.fillRect(cx+75,y-8,6,6);x.font='10px Segoe UI';x.fillText(name,cx+89,y);x.fillStyle='#b3cdb9';x.fillText(String(data.find(v=>v.name===name)?.value||0),w-30,y);});$('severity').setAttribute('aria-label',data.map(d=>d.name+': '+d.value).join(', '));}
async function overview(){const d=await api('dashboard/stats');const cards=[['Total de agentes','agents_total'],['Agentes online','agents_online'],['Agentes offline','agents_offline'],['Eventos em 24h','events_24h'],['Alertas ativos','alerts_active'],['Alertas críticos','alerts_critical']];$('kpis').replaceChildren(...cards.map(([label,key])=>{const card=element('article',undefined,'kpi');card.append(element('small',label),element('strong',d[key].toLocaleString('pt-BR')));return card;}));timeline(d.timeline);severity(d.by_severity);bars('types',d.by_type.sort((a,b)=>b.value-a.value));bars('machines',d.top_machines);}
async function agents(){let data=await api('agents?limit=100&offset='+offsets.agents);if(!data.length&&offsets.agents>0){offsets.agents=Math.max(0,offsets.agents-100);data=await api('agents?limit=100&offset='+offsets.agents);}const body=$('agents-body');body.replaceChildren();for(const a of data){const row=element('tr'),coverage=element('button',a.version,'row-action');coverage.append(element('small','Ver cobertura de proteção'));coverage.onclick=()=>protectionDetail(a);[a.hostname,badge(a.status),a.ip,a.os,coverage,formatTime(a.last_heartbeat),a.pending].forEach(v=>cell(row,v));const remove=element('button','Excluir','danger-button');remove.setAttribute('aria-label','Excluir agente '+a.hostname);remove.onclick=()=>confirmAgentDeletion(a);cell(row,remove);body.append(row);}if(!data.length)empty(body,8);pager('agents',data.length);}
function confirmAgentDeletion(agent){
  const body=showDetail('Excluir agente');
  body.append(element('p','Máquina: '+agent.hostname),element('p','ID: '+agent.id),element('p','A exclusão é permanente: remove o cadastro e todos os eventos, alertas e heartbeats deste agente no servidor. A credencial deixa de funcionar.'),element('p','O programa instalado na máquina não será desinstalado. Pare ou desinstale o serviço nessa máquina para encerrar a coleta.'));
  const form=element('form'),label=element('label','Digite o nome exato da máquina para confirmar:'),input=element('input');input.type='text';input.autocomplete='off';input.required=true;input.maxLength=255;label.append(input);
  const error=element('p');error.setAttribute('role','alert');
  const actions=element('div',undefined,'delete-actions'),cancel=element('button','Cancelar','subtle'),confirm=element('button','Excluir permanentemente','danger-button');cancel.type='button';confirm.type='submit';confirm.disabled=true;
  let deleting=false;
  input.oninput=()=>{confirm.disabled=deleting||input.value!==agent.hostname;};cancel.onclick=()=>$('detail').close();
  form.onsubmit=async e=>{e.preventDefault();if(deleting||input.value!==agent.hostname)return;deleting=true;confirm.disabled=true;cancel.disabled=true;input.disabled=true;error.textContent='';try{await api('agents/'+encodeURIComponent(agent.id),{method:'DELETE',body:JSON.stringify({confirm_name:input.value})});$('detail').close();await refresh();notice('Agente excluído: '+agent.hostname+'. Histórico removido e credencial invalidada.');}catch(err){error.textContent=err.message;deleting=false;confirm.disabled=false;cancel.disabled=false;input.disabled=false;}};
  actions.append(cancel,confirm);form.append(label,error,actions);body.append(form);input.focus();
}
function showDetail(title){$('detail-title').textContent=title;$('detail-body').replaceChildren();if(!$('detail').open)$('detail').showModal();return $('detail-body');}
async function events(){const p=filters('event-filters');p.set('offset',offsets.events);const data=await api('events?'+p);const body=$('events-body');body.replaceChildren();for(const e of data){const row=element('tr');const title=eventLabels[e.event_type]||e.event_type;const button=element('button',title,'row-action');button.append(element('small',e.event_type));button.onclick=()=>eventDetail(e);[formatTime(e.timestamp),e.hostname,button,badge(e.severity),[e.process?.name,e.user].filter(Boolean).join(' / '),displayLabels[e.detection_status]||e.detection_status].forEach(v=>cell(row,v));body.append(row);}if(!data.length)empty(body,6);pager('events',data.length);}
async function alertDetail(id){try{const a=await api('alerts/'+id),help=helpFor(a);const body=showDetail(help.title);body.append(badge(a.severity),element('p',`Máquina: ${a.hostname} · Usuário: ${a.user||'não informado'}`),element('p',`Pontuação de risco: ${a.risk_score}/100 · Confiança da análise: ${displayLabels[a.confidence]||a.confidence}`),element('p','A pontuação ajuda a priorizar a revisão; não é uma porcentagem de certeza de invasão.'),element('h3','O que aconteceu?'),element('p',help.description),element('h3','Por que o sistema chamou atenção?'),element('p',explainEvidence(a)),element('h3','O que verificar agora?'),element('p',help.action),element('p','Um alerta pede revisão. Atividades autorizadas também podem acionar regras.'));
body.append(element('p','A gravidade do evento original pode ser diferente da gravidade do alerta: a regra avalia o contexto e a sequência.'));
if(occurrenceText(a)){body.append(element('h3','Ocorrências desta regra'),element('p',occurrenceText(a)),element('p',`Janela: ${formatTime(a.occurrence_window_start)} até ${formatTime(a.occurrence_window_end)}. A contagem inclui alertas resolvidos e representa registros de alerta, não uma contagem comprovada de invasões ou de atacantes.`));}
if(a.rule_id==='TELEMETRY_LOST')body.append(element('p',`Último sinal: ${formatTime(a.evidence?.last_heartbeat)}. Prazo configurado: ${a.evidence?.timeout_seconds??'não informado'} segundos.`));
const list=element('div');for(const e of a.events||[]){const item=element('details',undefined,'event-card');item.append(element('summary',`${formatTime(e.timestamp)} — ${eventLabels[e.event_type]||e.event_type||'Registro relacionado'}`),eventFacts(e));list.append(item);}if(list.childNodes.length){body.append(element('h3','Atividades relacionadas — clique para expandir'),list);}
technicalSection(body,'Ver regra e motivo originais',{regra:a.rule_id,titulo:a.title,descricao:a.description,motivo:a.reason});technicalSection(body,'Ver condições técnicas da regra',a.evidence);technicalSection(body,'Ver registros técnicos completos',a.events);body.append(element('p','Concluir apaga do histórico todos os alertas desta mesma regra e máquina, inclusive os já resolvidos. Os eventos originais permanecem disponíveis; novas ocorrências poderão gerar novos alertas.'));const resolve=element('button','Concluir e apagar alertas iguais desta máquina');resolve.onclick=async()=>{resolve.disabled=true;try{const result=await api('alerts/'+id+'/complete',{method:'POST'});$('detail').close();offsets.alerts=0;await refresh();notice(`${result.deleted_alerts} alerta(s) removido(s). Eventos originais preservados.`);}catch(err){notice(err.message);resolve.disabled=false;}};body.append(resolve);}catch(err){notice(err.message);}}
async function alerts(){const p=filters('alert-filters');p.set('offset',offsets.alerts);const data=await api('alerts?'+p);const body=$('alerts-body');body.replaceChildren();for(const a of data){const help=helpFor(a);const row=element('tr'),button=element('button',help.title,'row-action');button.append(element('small',help.description),element('small','Ver explicação e orientação · '+a.rule_id));if(occurrenceText(a))button.append(element('strong',occurrenceText(a)));button.onclick=()=>alertDetail(a.id);[badge(a.severity),button,a.hostname,a.user,formatTime(a.created_at),a.risk_score+'/100',displayLabels[a.status]||a.status].forEach(v=>cell(row,v));body.append(row);}if(!data.length)empty(body,7);pager('alerts',data.length);}
async function refresh(){if(!token||busy)return;busy=true;const p=page();$('page-title').textContent=names[p];pages.forEach(id=>$(id).hidden=id!==p);document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('active',a.hash==='#'+p));try{await ({overview,agents,events,alerts,exclusions}[p])();securityNotices();$('connection').textContent='Atualizado às '+new Date().toLocaleTimeString('pt-BR');notice('');}catch(err){notice(err.message);$('connection').textContent='Consulta indisponível';}finally{busy=false;}}
// Translate labels without changing the values submitted to the API.
document.querySelectorAll('select[name="severity"] option').forEach(o=>{if(displayLabels[o.value]){const value=o.value;o.value=value;o.textContent=displayLabels[value];}});
document.querySelectorAll('#alerts th').forEach(h=>{if(h.textContent==='Regra / descrição')h.textContent='O que aconteceu / explicação';if(h.textContent==='Severidade')h.textContent='Nível de atenção';});
document.querySelectorAll('#agents th').forEach(h=>{if(h.textContent==='Último heartbeat')h.textContent='Último sinal recebido';if(h.textContent==='Pendentes')h.textContent='Eventos aguardando envio';});
document.querySelector('#alerts .intro').textContent='Veja o que aconteceu, por que merece atenção e o que conferir. Clique em um alerta para entender os detalhes.';
document.querySelector('#events .intro').textContent='Atividades registradas nos computadores. Clique em uma atividade para conferir o registro original.';
const coverageNote=element('p','Online significa que o agente se comunica. Não significa que a máquina está livre de ameaças. Em Agentes, clique na versão para consultar a cobertura de proteção.', 'coverage-note');$('overview').append(coverageNote);
$('login-form').onsubmit=async e=>{e.preventDefault();token=$('admin-token').value.trim();try{await api('agents?limit=1');$('admin-token').value='';$('login').hidden=true;await refresh();}catch(err){token='';notice(err.message);}};
$('logout').onclick=()=>{token='';$('login').hidden=false;pages.forEach(id=>$(id).hidden=true);$('detail').close();$('detail-body').replaceChildren();['agents-body','events-body','alerts-body','exclusions-body','ip-list'].forEach(id=>$(id).replaceChildren());$('connection').textContent='Não conectado';};
$('close-detail').onclick=()=>$('detail').close();
for(const [form,p] of [['event-filters','events'],['alert-filters','alerts']])$(form).onsubmit=e=>{e.preventDefault();offsets[p]=0;refresh();};
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>{offsets[b.dataset.page]=Math.max(0,offsets[b.dataset.page]+Number(b.dataset.delta)*100);refresh();});
window.addEventListener('hashchange',refresh);updateClock();setInterval(updateClock,1000);
const manualRefresh=element('button','Atualizar agora','subtle');
manualRefresh.title='O painel atualiza automaticamente a cada 5 minutos. Clique para consultar agora.';
manualRefresh.onclick=()=>refresh();document.querySelector('.header-right').append(manualRefresh);
$('overview').append(element('p','Atualização automática: a cada 5 minutos. Para consultar antes, use Atualizar agora.','coverage-note'));
setInterval(()=>{if(!document.hidden)refresh();},300000);

// Appended to reviewed dashboard variants by the host updater.
function openEmergencyPurge(){
  if(!token){notice('Entre como administrador para usar a limpeza de emergência.');return;}
  const dialog=document.createElement('dialog'), form=document.createElement('form');
  const title=element('h2','Emergência: apagar eventos e alertas');
  const explanation=element('p','Exclusão definitiva de TODOS os eventos e alertas da HOST. Cadastros e credenciais ficam preservados. Filas dos agentes não são apagadas: registros pendentes podem chegar depois. Esta ação não corrige bloqueios do banco nem garante redução do arquivo em disco.');
  const secret=document.createElement('input');secret.type='password';secret.autocomplete='off';secret.required=true;
  secret.setAttribute('aria-label','Digite novamente o token de administrador');secret.placeholder='Digite novamente o token de administrador';
  const phrase=document.createElement('input');phrase.required=true;phrase.autocomplete='off';
  phrase.setAttribute('aria-label','Digite APAGAR EVENTOS E ALERTAS');phrase.placeholder='APAGAR EVENTOS E ALERTAS';
  const error=element('p','');error.setAttribute('role','alert');
  const confirm=element('button','Apagar definitivamente');confirm.type='submit';confirm.disabled=true;
  const cancel=element('button','Cancelar');cancel.type='button';let working=false;
  function ready(){confirm.disabled=working||!secret.value||phrase.value!=='APAGAR EVENTOS E ALERTAS';}
  secret.oninput=phrase.oninput=ready;
  function close(){secret.value='';phrase.value='';dialog.close();dialog.remove();}
  cancel.onclick=close;dialog.oncancel=e=>{e.preventDefault();if(!working)close();};
  form.onsubmit=async e=>{
    e.preventDefault();if(working||confirm.disabled)return;working=true;ready();cancel.disabled=true;
    let fresh=secret.value;secret.value='';error.textContent='Aguarde a confirmação do servidor. Não repita a operação.';
    try{
      const pending=fetch('/api/v1/admin/emergency/purge-history',{method:'POST',headers:{
        'Authorization':'Bearer '+token,'X-Emergency-Token':fresh,'Content-Type':'application/json'},
        body:JSON.stringify({confirmation:phrase.value})});fresh='';
      const response=await pending;
      if(!response.ok)throw new Error(response.status===401?'Token administrativo não aceito. Digite novamente.':response.status===503?'Limpeza não concluída; o banco reverteu a operação. Verifique a saúde da HOST.':'Não foi possível confirmar a limpeza. Confira o painel antes de tentar novamente.');
      const result=await response.json();close();await refresh();
      notice(`Limpeza concluída: ${result.deleted.events} eventos e ${result.deleted.alerts} alertas apagados. Cadastros preservados.`);
    }catch(err){error.textContent=err.message;working=false;cancel.disabled=false;ready();}
    finally{fresh='';secret.value='';}
  };
  form.append(title,explanation,secret,phrase,error,confirm,cancel);dialog.append(form);document.body.append(dialog);dialog.showModal();
}
const emergencyPurgeButton=element('button','Limpeza de emergência');
emergencyPurgeButton.type='button';emergencyPurgeButton.onclick=openEmergencyPurge;
document.querySelector('.header-right').append(emergencyPurgeButton);

eventLabels['file.download_observed']='Novo arquivo ou alteração em Downloads';
const originalDownloadEventFacts=eventFacts;
eventFacts=function(e){
  const facts=originalDownloadEventFacts(e);
  if(e.event_type!=='file.download_observed')return facts;
  const raw=e.raw_event||{};
  const add=(label,value)=>facts.append(element('dt',label),element('dd',String(value)));
  add('Origem confirmada como download?','Não: também pode ser cópia ou alteração local');
  add('Extensão',raw.extension||'Sem extensão');add('Tamanho em bytes',raw.size_bytes??'Não informado');
  add('Link encontrado',raw.link_found===true?'Sim — CRÍTICO por política, mesmo legítimo':'Não encontrado nos elementos analisados; não garante ausência');
  const status={link_found:'Link identificado; nenhum endereço foi acessado',
    text_no_link_found:'Texto analisado sem link reconhecido',pdf_no_link_in_supported_elements:'PDF: nenhum link no texto/anotações analisados',
    office_supported_elements_only:'Office: texto e relações externas analisados',unsupported_format:'Formato não suportado para análise de links',
    encrypted_pdf:'PDF protegido por senha; análise indisponível',size_limit:'Arquivo excede o limite de 8 MiB',page_limit:'PDF excede o limite de 100 páginas',
    expanded_size_limit:'Conteúdo expandido excede o limite',invalid_pdf:'PDF inválido ou incompatível',invalid_office:'Documento Office inválido ou incompatível',
    analysis_timeout:'Análise excedeu o limite de tempo',memory_limit:'Análise excedeu o limite de memória',
    analysis_failed:'Não foi possível concluir a análise',analysis_start_failed:'Não foi possível iniciar o analisador',
    read_failed:'Arquivo indisponível para leitura',pdf_decoder_missing:'Leitor PDF ausente'};
  add('Resultado da análise',status[raw.analysis_status]||raw.analysis_status||'Não informado');
  if(['.py','.vbs','.htm','.bat'].includes(raw.extension))add('Política da extensão','CRÍTICO por política administrativa; não comprova malware');
  return facts;
};

// Display the operational limits of the explicitly selected ingestion policy.
(() => {
  for (const option of document.querySelectorAll('select[name="severity"] option')) {
    if (option.value === 'LOW') option.remove();
  }
  for (const section of ['overview', 'events', 'alerts']) {
    const parent = document.getElementById(section);
    if (!parent || parent.querySelector('[data-review-policy]')) continue;
    const note = document.createElement('p');
    note.dataset.reviewPolicy = 'true';
    note.className = 'footnote';
    note.textContent = 'Política ativa: novos eventos BAIXOS são descartados na HOST; alertas BAIXOS e TELEMETRY_LOST não são gerados. O histórico correspondente fica oculto. A ausência desses registros reduz a detecção de varreduras e DoS; ausência de alerta não confirma ausência de ataque.';
    parent.prepend(note);
  }
})();

(() => {
  const previousFacts=eventFacts;
  eventFacts=function(e){
    const facts=previousFacts(e),raw=e.raw_event||{};
    if(e.event_type!=='file.download_observed')return facts;
    const add=(label,value)=>facts.append(element('dt',label),element('dd',value));
    if(raw.initial_observation===true)add('Observação inicial','Arquivo já existente, revisado após a atualização; não comprova download recente');
    if(raw.extension==='.dll')add('DLL em Downloads','ALTO por política; somente metadados, sem executar ou carregar a biblioteca');
    const statuses={pdf_no_extractable_text:'Sem texto extraível; links em imagens não puderam ser verificados',
      pdf_annotation_limit:'Análise parcial: limite de anotações',pdf_action_limit:'Análise parcial: limite de ações',
      pdf_text_limit:'Análise parcial: limite de texto',page_limit:'Análise parcial: mais de 100 páginas',
      encrypted_pdf:'PDF protegido por senha',size_limit:'Mais de 8 MiB',analysis_timeout:'Tempo de análise excedido',
      invalid_pdf:'Não foi possível interpretar o PDF',memory_limit:'Limite de memória',
      analysis_start_failed:'Analisador não iniciou',analysis_failed:'Analisador falhou',pdf_decoder_missing:'Leitor PDF ausente'};
    if(raw.analysis_incomplete===true)add('Revisão necessária',statuses[raw.analysis_status]||'Análise incompleta; não significa arquivo seguro');
    return facts;
  };
})();

// Exclusions page: folders, extensions, programs and remote IPs managed from the panel (administrator token).
displayLabels.excluded='Ignorado (exclusão)';
const exclusionKinds={folder:'Pasta',extension:'Extensão',program:'Programa'};
const exclusionHelp={
  folder:['Pasta: nome ou caminho completo','123  ou  C:\\Users\\Maria\\123','Só o nome (ex.: 123) ignora qualquer pasta com esse nome, com as subpastas. O caminho completo ignora só aquela pasta.',true],
  extension:['Extensões (separe com vírgula)','.py, .vbs','Ignora arquivos com essas extensões. Programas e conexões continuam monitorados.',true],
  program:['Programa: caminho completo do .exe','C:\\Program Files\\Backup\\backup.exe','Ignora tudo o que esse programa faz. Só o arquivo nesse caminho: um programa com o mesmo nome em outra pasta continua monitorado. Programas costumam gerar muitos eventos: por isso o padrão é descartar.',false]
};
function exclusionKindChanged(){const help=exclusionHelp[$('exclusion-kind').value];$('exclusion-value-label').textContent=help[0];$('exclusion-value').placeholder=help[1];$('exclusion-hint').textContent=help[2];$('exclusion-keep').checked=help[3];}
$('exclusion-kind').onchange=exclusionKindChanged;exclusionKindChanged();
async function exclusions(){
  if(!exclusionToken){lockExclusions();return;}
  let data;
  try{data=await api('exclusions',{headers:exclusionHeaders()});}
  catch(err){if(err.status===403||err.status===503){lockExclusions(err.status===403?'Token de exclusão incorreto. Confira o arquivo exclusion-token.txt no servidor.':'O servidor ainda não tem token de exclusão: reinicie o SIEM para gerá-lo.');return;}throw err;}
  $('exclusion-unlock').hidden=true;$('exclusion-content').hidden=false;
  const select=$('exclusion-machine'),chosen=select.value;
  select.replaceChildren(new Option('Todas as máquinas','*'),...data.machines.map(name=>new Option(name,name)));
  if([...select.options].some(o=>o.value===chosen))select.value=chosen;
  const body=$('exclusions-body');body.replaceChildren();
  for(const x of data.exclusions){
    const row=element('tr');
    const toggle=element('button',x.enabled?'Desativar':'Ativar','subtle');
    toggle.onclick=async()=>{const headers=await confirmExclusionChange(x.enabled?`Desativar a exclusão "${x.value}" (${x.machine})? Esses eventos voltam a gerar alertas.`:`Reativar a exclusão "${x.value}" (${x.machine})?`);if(!headers)return;toggle.disabled=true;try{await api('exclusions/'+encodeURIComponent(x.id),{method:'PATCH',headers,body:JSON.stringify({enabled:!x.enabled})});await refresh();notice(x.enabled?'Exclusão desativada: volta a alertar.':'Exclusão reativada.');}catch(err){notice(err.status===403?'Token de exclusão incorreto. Nada foi alterado.':err.message);toggle.disabled=false;}};
    const remove=element('button','Remover','danger-button');remove.setAttribute('aria-label','Remover exclusão '+x.value);
    remove.onclick=async()=>{const headers=await confirmExclusionChange(`Remover a exclusão "${x.value}" (${x.machine})? Esses eventos voltam a gerar alertas.`);if(!headers)return;remove.disabled=true;try{await api('exclusions/'+encodeURIComponent(x.id),{method:'DELETE',headers});await refresh();notice('Exclusão removida.');}catch(err){notice(err.status===403?'Token de exclusão incorreto. Nada foi alterado.':err.message);remove.disabled=false;}};
    const actions=element('div',undefined,'exclusion-actions');actions.append(toggle);
    if(x.expires_at){const renew=element('button','Renovar','subtle');renew.onclick=async()=>{const choice=validityChoice(7);const headers=await confirmExclusionChange(`Renovar a validade da exclusão "${x.value}" (${x.machine})?`,choice);if(!headers)return;const days=Number(choice.querySelector('select').value);renew.disabled=true;try{await api('exclusions/'+encodeURIComponent(x.id),{method:'PATCH',headers,body:JSON.stringify({renew_days:days})});await refresh();notice(days?`Exclusão renovada: vale por mais ${days} dia(s).`:'Exclusão renovada: agora sem prazo.');}catch(err){notice(err.status===403?'Token de exclusão incorreto. Nada foi alterado.':err.message);renew.disabled=false;}};actions.append(renew);}
    actions.append(remove);
    const situation={active:['Ativa','badge active'],disabled:['Desativada','badge resolved'],expired:['Vencida','badge expired']}[x.status]||['Ativa','badge active'];
    const validity=x.expires_at?(x.status==='expired'?'Venceu em ':'Até ')+formatTime(x.expires_at):'Sem prazo';
    [exclusionKinds[x.kind]||x.kind,x.value,x.machine,x.keep_events?'Guardados, sem alerta':'Descartados',x.description||'—',x.created_at?formatTime(x.created_at):'Arquivo de regras',validity,element('span',...situation),actions].forEach(v=>cell(row,v));
    body.append(row);
  }
  if(!data.exclusions.length){const row=element('tr'),td=element('td','Nenhuma exclusão cadastrada.','empty');td.colSpan=9;row.append(td);body.append(row);}
  const list=$('ip-list');list.replaceChildren();
  for(const item of data.remote_ips){
    const chip=element('span',item.ip,'ip-chip'+(item.fixed?' fixed':''));
    if(item.fixed){chip.title='Fixo no programa do servidor';chip.append(element('small',' fixo'));}
    else{const x=element('button','×','ip-remove');x.type='button';x.setAttribute('aria-label','Remover IP '+item.ip);x.onclick=async()=>{const headers=await confirmExclusionChange(`Remover o IP ${item.ip} da lista? Ele volta a gerar alertas de rede.`);if(!headers)return;x.disabled=true;try{await api('exclusions/remote-ips/'+encodeURIComponent(item.ip),{method:'DELETE',headers});await refresh();notice('IP removido: '+item.ip+'. Volta a gerar alertas de rede.');}catch(err){notice(err.status===403?'Token de exclusão incorreto. Nada foi alterado.':err.message);x.disabled=false;}};chip.append(x);}
    list.append(chip);
  }
  const history=await api('exclusions/history?limit=100',{headers:exclusionHeaders()}),log=$('exclusion-history');log.replaceChildren();
  for(const item of history){const row=element('tr',undefined,item.action.endsWith('_failed')?'history-failure':'');[formatTime(item.timestamp),item.detail,item.ip||'—'].forEach(v=>cell(row,v));log.append(row);}
  if(!history.length){const row=element('tr'),td=element('td','Nenhuma alteração registrada ainda.','empty');td.colSpan=3;row.append(td);log.append(row);}
}
function validityChoice(days){const label=element('label','Validade'),select=element('select');for(const [value,text] of [[0,'Sem prazo'],[1,'1 dia'],[7,'7 dias'],[30,'30 dias'],[90,'90 dias'],[365,'1 ano']])select.append(new Option(text,value));select.value=String(days);label.append(select);return label;}
$('exclusion-form').onsubmit=async e=>{
  e.preventDefault();const form=e.target,button=form.querySelector('button[type="submit"]');button.disabled=true;
  const body={kind:$('exclusion-kind').value,value:$('exclusion-value').value.trim(),machine:$('exclusion-machine').value,keep_events:$('exclusion-keep').checked,description:form.elements.description.value.trim(),days:Number($('exclusion-days').value)||null};
  const kindName={folder:'pasta',extension:'extensão',program:'programa'}[body.kind];
  const headers=await confirmExclusionChange(`Adicionar exclusão de ${kindName} "${body.value}" em ${body.machine==='*'?'todas as máquinas':body.machine} (${body.keep_events?'guardar eventos, sem alerta':'descartar eventos'}, ${body.days?'vale por '+body.days+' dia(s)':'sem prazo'})?`);
  if(!headers){button.disabled=false;return;}
  try{const result=await api('exclusions',{method:'POST',headers,body:JSON.stringify(body)});$('exclusion-value').value='';form.elements.description.value='';await refresh();
    notice(`Exclusão adicionada (${body.machine==='*'?'todas as máquinas':body.machine}). ${result.resolved_alerts} alerta(s) ativo(s) marcado(s) como resolvido(s). Vale em poucos segundos.`);}
  catch(err){notice(err.status===403?'Token de exclusão incorreto. Nada foi alterado.':err.message);}finally{button.disabled=false;}
};
$('ip-form').onsubmit=async e=>{
  e.preventDefault();const button=e.target.querySelector('button[type="submit"]');const ips=$('ip-input').value.split(/[\s,;]+/).filter(Boolean);if(!ips.length)return;button.disabled=true;
  const headers=await confirmExclusionChange(`Ignorar ${ips.length} IP(s) nos alertas de rede: ${ips.slice(0,5).join(', ')}${ips.length>5?'...':''}?`);
  if(!headers){button.disabled=false;return;}
  try{const result=await api('exclusions/remote-ips',{method:'POST',headers,body:JSON.stringify({ips})});$('ip-input').value='';await refresh();notice(`${result.added} IP(s) ignorado(s) nos alertas de rede. ${result.resolved_alerts} alerta(s) ativo(s) marcado(s) como resolvido(s).`);}
  catch(err){notice(err.status===403?'Token de exclusão incorreto. Nada foi alterado.':err.message);}finally{button.disabled=false;}
};
const originalExclusionFacts=eventFacts;
eventFacts=function(e){const facts=originalExclusionFacts(e);if(e.exclusion_reason)facts.append(element('dt','Exclusão'),element('dd',e.exclusion_reason));return facts;};
// Exclusions tab requires its own token (X-Exclusion-Token), asked every time the tab is opened.
let exclusionToken='';
const exclusionUnlockHelp=$('exclusion-unlock-error').textContent;
function exclusionHeaders(){return {'X-Exclusion-Token':exclusionToken};}
function lockExclusions(message){
  exclusionToken='';$('exclusion-content').hidden=true;$('exclusion-unlock').hidden=false;
  ['exclusions-body','ip-list','exclusion-history'].forEach(id=>$(id).replaceChildren());
  $('exclusion-unlock-error').textContent=message||exclusionUnlockHelp;
  $('exclusion-token-input').value='';$('exclusion-token-input').focus();
}
$('exclusion-unlock').onsubmit=async e=>{e.preventDefault();exclusionToken=$('exclusion-token-input').value.trim();$('exclusion-token-input').value='';await refresh();};
$('exclusion-lock').onclick=()=>{lockExclusions('Aba bloqueada. Digite o token de exclusão para continuar.');};
window.addEventListener('hashchange',()=>{if(page()!=='exclusions')lockExclusions();});
$('logout').addEventListener('click',()=>{lockExclusions();$('security-banner').hidden=true;});
// Every change (add, remove, enable/disable) asks for the exclusion token again, in a confirmation dialog.
function confirmExclusionChange(message,extra){
  return new Promise(resolve=>{
    const dialog=document.createElement('dialog'),form=document.createElement('form');
    const input=document.createElement('input');input.type='password';input.autocomplete='off';input.required=true;input.placeholder='Token de exclusão';
    input.setAttribute('aria-label','Digite o token de exclusão para confirmar');
    const confirmButton=element('button','Confirmar');confirmButton.type='submit';
    const cancel=element('button','Cancelar','subtle');cancel.type='button';
    const actions=element('div',undefined,'delete-actions');actions.append(cancel,confirmButton);
    form.append(element('h2','Confirmar alteração'),element('p',message),...(extra?[extra]:[]),element('p','Digite o token de exclusão para confirmar.','exclusion-hint'),input,actions);
    dialog.className='confirm-dialog';dialog.append(form);document.body.append(dialog);
    const finish=value=>{input.value='';dialog.close();dialog.remove();resolve(value);};
    cancel.onclick=()=>finish(null);dialog.oncancel=e=>{e.preventDefault();finish(null);};
    form.onsubmit=e=>{e.preventDefault();const typed=input.value.trim();if(typed)finish({'X-Exclusion-Token':typed});};
    dialog.showModal();input.focus();
  });
}
// Summary on every page: exclusion changes and wrong tokens in the last 24 hours, validity ending soon or over.
// "Ok, visto" is kept only in this tab's memory, like the tokens (nothing is stored in the browser).
let securityBannerKey='',securityBannerSeen='';
async function securityNotices(){
  let n;try{n=await api('security/notices');}catch(err){return;}
  const parts=[];if(n.changes_24h)parts.push(`${n.changes_24h} alteração(ões) de exclusões`);if(n.failures_24h)parts.push(`${n.failures_24h} tentativa(s) com token errado`);
  let text=parts.length?`Nas últimas 24 horas: ${parts.join(' e ')}.`:'';
  if(n.expiring.length)text+=` ${n.expiring.length} exclusão(ões) vence(m) em até 3 dias: ${n.expiring.slice(0,3).map(x=>`"${x.value}" (${x.machine}, ${formatTime(x.expires_at)})`).join(', ')}.`;
  if(n.expired)text+=` ${n.expired} exclusão(ões) vencida(s): esses eventos voltaram a gerar alertas.`;
  if(text)text+=' Veja na aba Exclusões.';
  securityBannerKey=JSON.stringify([n.latest,n.expiring.length,n.expired]);
  $('security-banner-text').textContent=text.trim();$('security-banner').hidden=!text||securityBannerSeen===securityBannerKey;
}
$('security-banner-ok').onclick=()=>{securityBannerSeen=securityBannerKey;$('security-banner').hidden=true;};
