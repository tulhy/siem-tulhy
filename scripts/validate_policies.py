"""Read and validate editable policy without touching the database."""
import json
from pathlib import Path
from pydantic import ValidationError
from server.services.policy_files import ROOT,NAMES,validate_bundle

def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--directory',type=Path,default=ROOT/'rules')
    args=parser.parse_args()
    try:
        result=validate_bundle([json.loads((args.directory/name).read_text(encoding='utf-8-sig')) for name in NAMES])
    except ValidationError as exc:
        print(json.dumps(exc.errors(include_input=False,include_context=False),ensure_ascii=False,indent=2))
        return 1
    except (OSError,ValueError,UnicodeError) as exc:
        print('Configuracao invalida:',str(exc));return 1
    print('Configuracao valida:',len(result[1].rules),'regras gerais,',len(result[0].rules),'regras de usuarios.')
    print('Exclusoes ativas:',sum(e.enabled for e in result[1].path_exclusions))
    print('Programas ignorados:',', '.join(p for e in result[1].process_exclusions if e.enabled for p in e.paths) or 'nenhum')
    print('IPs remotos ignorados nos alertas de rede:',len(result[1].ignored_remote_ips))
    return 0

if __name__=='__main__':raise SystemExit(main())
