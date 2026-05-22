from flask import Blueprint

# إنشاء البلوبرنت
password_checker_bp = Blueprint(
    "password_checker",
    __name__,
    url_prefix="/api/password"
)

# استيراد الروتز بعد إنشاء البلوبرنت
from . import routes
