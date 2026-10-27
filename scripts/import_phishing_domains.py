"""Manual OpenPhish import: download indicators only; never visit listed sites."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
from urllib.parse import urlsplit
from uuid import uuid4

FEED='https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
MAX_BYTES=5_000_000
MAX_DOMAINS=10000

def parse_domains(content):
    from server.detection.rules import normalize_domain
    if len(content)>MAX_BYTES:raise ValueError('Lista maior que o limite permitido.')
    domains=set()
    for line in content.decode('utf-8-sig').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if any(c.isspace() for c in line):raise ValueError('Indicador invalido na lista.')
        parsed=urlsplit(line if '://' in line else 'https://'+line)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Indicador invalido na lista.')
        domains.add(normalize_domain(parsed.hostname))
        if len(domains)>MAX_DOMAINS:raise ValueError('Muitos dominios; lista anterior preservada.')
    if not domains:raise ValueError('Lista vazia; lista anterior preservada.')
    return sorted(domains)

def download():
    import httpx
    with httpx.Client(timeout=20,trust_env=False,follow_redirects=False) as client:
        with client.stream('GET',FEED) as response:
            response.raise_for_status()
            parts=[]
            size=0
            for part in response.iter_bytes():
                size+=len(part)
                if size>MAX_BYTES:raise ValueError('Lista maior que o limite permitido.')
                parts.append(part)
    return b''.join(parts)

def update_rule(root,content,source):
    from server.detection.rules import Rule
    domains=parse_domains(content)
    target=root/'rules/default_rules/security_policy.json'
    rules=json.loads(target.read_text(encoding='utf-8'))
    matches=[r for r in rules if r['id']=='SUSPICIOUS_DOMAIN']
    if len(matches)!=1:raise ValueError('Regra de dominios ausente ou duplicada.')
    rule=matches[0]
    condition=next(c for c in rule['conditions'] if c['field']=='raw_event.domain')
    condition.update(op='domain_suffix',value=domains)
    stamp=datetime.now(timezone.utc).isoformat(timespec='seconds')
    rule.update(severity='MEDIUM',enabled=True,description=f'Consulta DNS a dominio ou subdominio da lista {source}, atualizada em {stamp}, com {len(domains)} dominios. Consulta nao comprova visita. Hospedagem compartilhada pode gerar falsos positivos; revise o contexto.')
    for item in rules:Rule.model_validate(item)
    backup=root/'rules/backups'/('security_policy-'+uuid4().hex+'.json')
    backup.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(target,backup)
    temporary=target.with_name(target.name+'.'+uuid4().hex+'.updating')
    try:
        with temporary.open('x',encoding='utf-8') as stream:
            stream.write(json.dumps(rules,ensure_ascii=False,indent=2)+'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,target)
    finally:temporary.unlink(missing_ok=True)
    return len(domains),backup

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    options=parser.add_mutually_exclusive_group(required=True)
    options.add_argument('--openphish',action='store_true')
    options.add_argument('--file',type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    # Allow running the installed script directly without pip in the global runtime.
    sys.path.insert(0,str(root))
    content=download() if args.openphish else args.file.read_bytes()
    count,backup=update_rule(root,content,'OpenPhish Community' if args.openphish else 'local')
    print(f'Lista atualizada: {count} dominios. Nenhum site listado foi acessado.')
    print('Backup:',backup)
    print('Reinicie o servidor para carregar a lista. Agentes nao precisam ser atualizados.')

if __name__=='__main__':main()
