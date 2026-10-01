from typing import Tuple
from src.security.ml_risk.model import MLRiskPredictor
from src.security.risk.models import RiskLevel
from src.security.environment.manager import EnvironmentManager
from src.security.ml_risk.features import extract_features

class MLRiskPredictorAPI:
    def __init__(self, model_path: str):
        self.predictor = MLRiskPredictor.load(model_path)
        
    def predict_context_risk(self, env: EnvironmentManager, context_id: str) -> Tuple[float, RiskLevel]:
        """
        API to predict risk purely from observable environment state, without mutating.
        """
        features = extract_features(env, context_id)
        return self.predictor.predict(features)
