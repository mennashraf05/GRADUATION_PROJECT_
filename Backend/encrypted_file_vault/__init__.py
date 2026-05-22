from .routes import bp as vault_bp

def init_vault(app):
    app.register_blueprint(vault_bp)