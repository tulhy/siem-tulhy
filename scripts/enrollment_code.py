"""Create, list or revoke enrollment codes for new agents of this server (administrator, on the server)."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import ssl
import subprocess
from urllib.parse import urlparse
import httpx
from shared import enrollment
from scripts.enroll_remote import reachable_server
from scripts.local_lab import ROOT


def server(data):
    info_file = data/'server-info.json'
    if not info_file.is_file():
        raise ValueError('O servidor ainda nao foi iniciado em modo rede.')
    info = json.loads(info_file.read_text(encoding='utf-8'))
    if not info.get('lan') or info.get('server_ips') is None:
        raise ValueError('O servidor precisa estar em modo rede (cabo e Wi-Fi). Reinicie o SIEM e tente de novo.')
    token = (data/'admin-token.txt').read_text(encoding='utf-8').strip()
    return info, token


def build_code(info, secret):
    ca_pem = Path(info['certificate']).read_text(encoding='ascii')
    url = urlparse(info['server_url'])
    host = url.hostname if not url.hostname[0].isdigit() else None
    ips = [ip for ip in info['server_ips'] if not ip.startswith('192.168.56.')][:8]  # skip VirtualBox host-only
    return enrollment.encode(host, ips, url.port or 8443, enrollment.ca_fingerprint(ca_pem), secret)


def copy_to_clipboard(text):
    try:
        subprocess.run(['clip.exe'], input=text.encode('ascii'), check=True, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', default=str(ROOT/'data/local-lab'))
    parser.add_argument('--nome', help='Identificacao do codigo, ex.: Filial-financeiro')
    parser.add_argument('--horas', type=int, default=168, help='Validade em horas (padrao 7 dias)')
    parser.add_argument('--maquinas', type=int, default=50, help='Quantas maquinas podem usar o codigo')
    parser.add_argument('--listar', action='store_true')
    parser.add_argument('--revogar', metavar='ID')
    args = parser.parse_args()
    data = Path(args.data_dir).resolve()
    info, token = server(data)
    headers = {'Authorization':'Bearer '+token}
    context = ssl.create_default_context(cafile=info['certificate'])
    with httpx.Client(verify=context, timeout=15, trust_env=False) as client:
        base = reachable_server(client, info)+'/api/v1/enrollment-codes'
        if args.listar:
            rows = client.get(base, headers=headers).raise_for_status().json()
            for row in rows:
                state = 'REVOGADO' if row['revoked'] else 'vencido' if row['expires_at'] < datetime.now().timestamp() else 'ativo'
                print(f"{row['id']}  {state:8}  usos {row['uses']}/{row['max_uses']}  ate {datetime.fromtimestamp(row['expires_at']):%d/%m/%Y %H:%M}  {row['label']}")
            if not rows:
                print('Nenhum codigo criado.')
            return
        if args.revogar:
            client.delete(f'{base}/{args.revogar}', headers=headers).raise_for_status()
            print('Codigo revogado. Maquinas ja cadastradas continuam funcionando.')
            return
        label = args.nome if args.nome is not None else input('Identificacao do codigo (Enter para "cadastro"): ').strip() or 'cadastro'
        created = client.post(base, headers=headers, json={'label':label[:100], 'hours':args.horas,
                                                            'max_uses':args.maquinas}).raise_for_status().json()
    code = build_code(info, created['secret'])
    print('\nCODIGO DE CADASTRO (cole no instalador do agente):\n')
    print(code)
    print(f"\nValido ate {datetime.fromtimestamp(created['expires_at']):%d/%m/%Y %H:%M} para ate {created['max_uses']} maquinas.")
    print('Copiado para a area de transferencia.' if copy_to_clipboard(code) else 'Selecione e copie o codigo acima.')
    print('Trate o codigo como senha: quem o tiver pode cadastrar maquinas ate ele vencer.')
    print(f"Para cancelar: CRIAR_CODIGO_CADASTRO.cmd --revogar {created['id']}")


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, httpx.HTTPError) as exc:
        print('ERRO:', exc)
        raise SystemExit(1)
