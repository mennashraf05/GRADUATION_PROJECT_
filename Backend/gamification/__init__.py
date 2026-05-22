from gamification.routes import gamification_bp
from gamification.service import (
    GamificationService,
    critical_reduction_points,
    ensure_gamification_schema_initialized,
    score_improvement_points,
)

__all__ = [
    "GamificationService",
    "critical_reduction_points",
    "ensure_gamification_schema_initialized",
    "gamification_bp",
    "score_improvement_points",
]
