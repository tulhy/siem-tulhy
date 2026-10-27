"""Narrow HTTP policy exceptions; paths are not proof of file authenticity."""
HTTP_RULES = {'POSSIBLE_CLEARTEXT_HTTP', 'POSSIBLE_CLEARTEXT_HTTP_NO_DIRECTION'}
HTTP_PATHS = tuple(f'c:\\windows\\{folder}\\{name}'
                  for folder in ('system32','syswow64')
                  for name in ('spoolsv.exe','svchost.exe'))

def exempt_http(rule_id, body):
    if rule_id not in HTTP_RULES:
        return False
    process = body.get('process') or {}
    path = process.get('path')
    if not isinstance(path,str):
        return False
    path = path.replace('/','\\').casefold()
    return path in HTTP_PATHS and str(process.get('name') or '').casefold() == path.rsplit('\\',1)[-1]

def http_exception_sql():
    from sqlalchemy import and_, func, or_
    from server.models.tables import EventRow
    path = func.lower(func.replace(EventRow.body['process']['path'].as_string(), '/', '\\'))
    name = func.lower(EventRow.body['process']['name'].as_string())
    return func.coalesce(or_(*(and_(path == p, name == p.rsplit('\\',1)[-1]) for p in HTTP_PATHS)), False)
