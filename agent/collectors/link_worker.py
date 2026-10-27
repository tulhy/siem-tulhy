"""Bounded link-presence inspection. Never follows links or executes documents."""
import json
import re
import sys
from pathlib import Path
from zipfile import ZipFile, BadZipFile
sys.path.insert(0,str(Path(__file__).with_name('pdf_library.zip')))

MAX_BYTES=8*1024*1024
LINK=re.compile(r'(?i)(?:https?://|ftp://|www\.)[^\s<>"\x00]{3,}|mailto:[^\s<>"\x00]+@[^\s<>"\x00]+')
TEXT={'.txt','.csv','.json','.xml','.html','.htm','.md','.py','.vbs','.bat','.cmd','.ps1','.js','.css','.rtf','.log','.url'}

def scan(path):
    if path.stat().st_size>MAX_BYTES:return {'link_found':False,'analysis_status':'size_limit'}
    suffix=path.suffix.lower()
    if suffix=='.pdf':
        try:
            from pypdf import PdfReader
            from pypdf.errors import PdfReadError
        except ImportError:
            return {'link_found':False,'analysis_status':'pdf_decoder_missing'}
        try:
            reader=PdfReader(str(path),strict=False)
            if reader.is_encrypted:return {'link_found':False,'analysis_status':'encrypted_pdf'}
            visited=set();budget=[512];limited=[None];has_text=False
            def action_has_link(ref, depth=0):
                if not ref:return False
                if depth>8 or budget[0]<=0:
                    limited[0]='pdf_action_limit';return False
                action=ref.get_object() if hasattr(ref,'get_object') else ref
                if id(action) in visited:return False
                visited.add(id(action));budget[0]-=1
                if isinstance(action,list):return any(action_has_link(item,depth+1) for item in action)
                if not hasattr(action,'get'):return False
                if action.get('/URI') or (action.get('/S') in ('/GoToR','/GoToE') and action.get('/F')):return True
                return action_has_link(action.get('/Next'),depth+1)
            def additional_links(ref):
                value=ref.get_object() if hasattr(ref,'get_object') else ref
                return hasattr(value,'values') and any(action_has_link(item) for item in value.values())
            catalog=reader.trailer['/Root'].get_object()
            if action_has_link(catalog.get('/OpenAction')) or additional_links(catalog.get('/AA')):
                return {'link_found':True,'analysis_status':'link_found'}
            for page in reader.pages[:100]:
                if additional_links(page.get('/AA')):return {'link_found':True,'analysis_status':'link_found'}
                if len(page.get('/Annots',[]))>200:limited[0]='pdf_annotation_limit'
                for ref in page.get('/Annots',[])[:200]:
                    annotation=ref.get_object()
                    if action_has_link(annotation.get('/A')) or additional_links(annotation.get('/AA')):
                        return {'link_found':True,'analysis_status':'link_found'}
                text=page.extract_text() or ''
                has_text=has_text or bool(text.strip())
                if len(text)>500_000:limited[0]='pdf_text_limit'
                if LINK.search(text[:500_000]):return {'link_found':True,'analysis_status':'link_found'}
            status=('page_limit' if len(reader.pages)>100 else limited[0] or
                    ('pdf_no_link_in_supported_elements' if has_text else 'pdf_no_extractable_text'))
            return {'link_found':False,'analysis_status':status}
        except (PdfReadError,ValueError,TypeError,KeyError,RecursionError,AttributeError):
            return {'link_found':False,'analysis_status':'invalid_pdf'}
    if suffix in {'.docx','.xlsx','.pptx'}:
        try:
            total=0
            with ZipFile(path) as archive:
                for entry in archive.infolist()[:500]:
                    if not entry.filename.endswith(('.xml','.rels')):continue
                    total+=entry.file_size
                    if total>MAX_BYTES:return {'link_found':False,'analysis_status':'expanded_size_limit'}
                    text=archive.read(entry).decode('utf-8',errors='replace')
                    # Office namespaces are not document hyperlinks. Look only at
                    # external relationship targets and visible text nodes.
                    targets=re.findall(r'Target=["\']([^"\']+)["\'][^>]*TargetMode=["\']External|TargetMode=["\']External["\'][^>]*Target=["\']([^"\']+)',text)
                    visible=re.findall(r'<(?:\w+:)?t(?:\s[^>]*)?>([^<]*)</',text)
                    if any(LINK.search(s) for pair in targets for s in pair) or any(LINK.search(s) for s in visible):
                        return {'link_found':True,'analysis_status':'link_found'}
            return {'link_found':False,'analysis_status':'office_supported_elements_only'}
        except (BadZipFile,RuntimeError,ValueError):return {'link_found':False,'analysis_status':'invalid_office'}
    if suffix not in TEXT:return {'link_found':False,'analysis_status':'unsupported_format'}
    raw=path.read_bytes()
    text=raw.decode('utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig',errors='replace')
    found=bool(LINK.search(text))
    return {'link_found':found,'analysis_status':'link_found' if found else 'text_no_link_found'}

if __name__=='__main__':
    try:result=scan(Path(sys.argv[1]))
    except OSError:result={'link_found':False,'analysis_status':'read_failed'}
    print(json.dumps(result))
