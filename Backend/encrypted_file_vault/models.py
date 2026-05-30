from datetime import datetime
from extensions import db


class VaultDocument(db.Model):
    __bind_key__ = "vault"
    __tablename__ = "vault_documents"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user_id = db.Column(db.Integer, nullable=False)

    file_hash = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(32), nullable=False)

    offline_enabled = db.Column(db.Boolean, default=False, nullable=False)

    signature = db.Column(db.Text)
    hmac_key = db.Column(db.String(44))
