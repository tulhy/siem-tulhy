"""Export the panel's Events and Alerts to CSV files that open directly in Excel. Read-only."""
import argparse
import csv
from datetime import datetime, timedelta
import os
from pathlib import Path
import sys
import time
from urllib.parse import quote
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

EVENT_COLUMNS = ['Data e hora', 'Maquina', 'Tipo', 'Severidade no painel', 'Severidade do agente', 'Usuario',
                 'Processo', 'Caminho do processo', 'Arquivo', 'IP remoto', 'Porta remota', 'IP local', 'Porta local',
                 'Deteccao', 'Fonte', 'ID do evento']
ALERT_COLUMNS = ['Data e hora', 'Maquina', 'Alerta', 'Regra', 'Severidade', 'Status', 'Risco', 'Confianca',
                 'Usuario', 'Motivo', 'Eventos relacionados', 'ID do alerta']


def read_only(database):
    if not database.is_file():
        raise ValueError(f'Banco de dados nao encontrado: {database}')
    # mode=ro: this tool can never change the panel's data, even while the SIEM is running.
    url = 'sqlite:///file:' + quote(database.resolve().as_posix(), safe='/:') + '?mode=ro&uri=true'
    return create_engine(url, connect_args={'timeout': 30})


def when(epoch):
    return datetime.fromtimestamp(epoch).strftime('%d/%m/%Y %H:%M:%S') if epoch else ''


def text(value):
    # Excel would run a cell starting with = + - @ as a formula; collected data must stay plain text.
    value = '' if value is None else str(value)
    return "'" + value if value[:1] in ('=', '+', '-', '@') else value


def write_csv(path, header, rows):
    count = 0
    with open(path, 'w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.writer(stream, delimiter=';')
        writer.writerow(header)
        for row in rows:
            writer.writerow([text(value) for value in row])
            count += 1
    return count


def events(db, since, machine):
    from server.models.tables import EventRow
    from server.api.routes import displayed_event_severity
    from server.services.visibility import visible_events
    query = (select(EventRow, displayed_event_severity()).where(visible_events(), EventRow.timestamp >= since)
             .order_by(EventRow.timestamp.desc()))
    if machine:
        query = query.where(func.lower(EventRow.hostname) == machine.casefold())
    for row, shown in db.execute(query).yield_per(1000):
        body = row.body or {}
        process, file = body.get('process') or {}, body.get('file') or {}
        yield [when(row.timestamp), row.hostname, row.event_type, shown, body.get('severity', row.severity), row.user,
               row.process, process.get('path'), file.get('path'), row.ip, row.port, row.local_ip, row.local_port,
               row.detection_status, body.get('source'), row.id]


def alerts(db, since, machine):
    from server.models.tables import Alert, Agent
    from server.services.visibility import visible_alerts
    query = (select(Alert, Agent.hostname).join(Agent, Agent.id == Alert.agent_id)
             .where(visible_alerts(), Alert.created_at >= since).order_by(Alert.created_at.desc()))
    if machine:
        query = query.where(func.lower(Agent.hostname) == machine.casefold())
    for row, hostname in db.execute(query).yield_per(1000):
        yield [when(row.created_at), hostname, row.title, row.rule_id, row.severity, row.status, row.risk_score,
               row.confidence, row.user, row.reason, len(row.event_ids or []), row.id]


def default_output():
    desktop = Path(os.environ.get('USERPROFILE', str(Path.home())))/'Desktop'
    return (desktop if desktop.is_dir() else Path.home())/'Tulhy - Exportacoes'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', default=str(ROOT/'data/local-lab'))
    parser.add_argument('--dias', type=int, help='Quantos dias para tras (padrao 7)')
    parser.add_argument('--maquina', help='Nome da maquina como aparece no painel (padrao: todas)')
    parser.add_argument('--saida', help='Pasta onde salvar as planilhas')
    args = parser.parse_args()
    interactive = args.dias is None and args.maquina is None
    days = args.dias
    if days is None:
        typed = input('Exportar quantos dias para tras? [7]: ').strip() if interactive else ''
        days = int(typed) if typed else 7
    if not 1 <= days <= 3650:
        raise ValueError('Use de 1 a 3650 dias.')
    machine = args.maquina
    if machine is None and interactive:
        machine = input('Maquina (nome no painel; Enter = todas): ').strip()
    since = time.time() - days*86400
    output = Path(args.saida) if args.saida else default_output()
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y-%m-%d_%H%M')
    suffix = f'_{machine}' if machine else ''
    engine = read_only(Path(args.data_dir)/'server.db')
    print('Lendo o banco do painel (somente leitura)...')
    with Session(engine) as db:
        events_file = output/f'eventos_{stamp}{suffix}.csv'
        alerts_file = output/f'alertas_{stamp}{suffix}.csv'
        total_events = write_csv(events_file, EVENT_COLUMNS, events(db, since, machine))
        total_alerts = write_csv(alerts_file, ALERT_COLUMNS, alerts(db, since, machine))
    engine.dispose()
    period = f"desde {(datetime.now()-timedelta(days=days)):%d/%m/%Y %H:%M}"
    print(f'\n{total_events} eventos e {total_alerts} alertas exportados ({period}{", maquina " + machine if machine else ""}).')
    print('Eventos:', events_file)
    print('Alertas:', alerts_file)
    print('Abra com duplo clique no Excel. Os arquivos tem dados das maquinas: nao compartilhe publicamente.')
    return output


if __name__ == '__main__':
    try:
        folder = main()
        if os.name == 'nt' and sys.stdin.isatty():
            os.startfile(folder)  # open the folder for the person who asked for the export
    except (OSError, ValueError) as exc:
        print('ERRO:', exc)
        raise SystemExit(1)
