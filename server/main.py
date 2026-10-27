from contextlib import asynccontextmanager
import html
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from server.settings import Settings, ROOT
from server.database.session import setup
from server.api.routes import router
from server.api.exclusions import router as exclusions_router, notices_router
from server.api.limits import BodyLimits
from shared.logging import configure
from server.detection.engine import DetectionEngine
from server.services.worker import Worker

def create_app(settings=None, background=True):
    settings = settings or Settings()
    @asynccontextmanager
    async def lifespan(app):
        settings.validate()
        configure()
        app.state.engine, app.state.sessions = setup(settings.database_url)
        app.state.detection = DetectionEngine(settings)
        with app.state.sessions() as db:
            app.state.detection.sync_rules(db)
        app.state.worker = Worker(app.state.sessions,app.state.detection,settings) if background else None
        if app.state.worker:
            app.state.worker.start()
        try:
            yield
        finally:
            if app.state.worker:
                app.state.worker.stop()
            app.state.engine.dispose()
    app = FastAPI(title='SIEM Tulhy', version='1.0.0', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.add_middleware(BodyLimits, settings=settings)
    app.include_router(router)
    app.include_router(exclusions_router)
    app.include_router(notices_router)
    app.mount('/static',StaticFiles(directory=ROOT/'dashboard/static'),name='static')
    @app.get('/',include_in_schema=False)
    def dashboard():
        page = (ROOT/'dashboard/templates/index.html').read_text(encoding='utf-8')
        if settings.site_name:
            site = html.escape(settings.site_name)
            page = (page.replace('CENTRAL DE SEGURANÇA', 'CENTRAL DE SEGURANÇA · ' + site.upper())
                        .replace('SIEM Tulhy · Central de Segurança', 'SIEM Tulhy · Central de Segurança · ' + site))
        return HTMLResponse(page)
    @app.get('/health')
    def health(request: Request):
        with request.app.state.engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        worker = request.app.state.worker
        if worker and not worker.healthy():
            return JSONResponse({'status':'degraded','component':'detection'},status_code=503)
        return {'status':'ok'}
    from fastapi.exceptions import RequestValidationError
    @app.exception_handler(RequestValidationError)
    async def invalid(request, exc):
        # Do not reflect supplied bodies, commands or secrets in errors.
        return JSONResponse(status_code=422, content={'detail':[{'loc':list(e['loc']),'type':e['type']} for e in exc.errors()]})
    return app

app = create_app()
