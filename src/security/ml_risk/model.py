import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestRegressor
from sklearn.exceptions import NotFittedError

from src.security.risk.scorer import determine_risk_level
from src.security.risk.models import RiskLevel
from src.security.ml_risk.features import FEATURE_NAMES

class MLRiskPredictor:
    def __init__(self, random_state: int = 42):
        self.model = RandomForestRegressor(n_estimators=100, random_state=random_state)
        self.is_fitted = False
        
    def train(self, X: np.ndarray, y: np.ndarray):
        if X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"Expected {len(FEATURE_NAMES)} features, got {X.shape[1]}")
        self.model.fit(X, y)
        self.is_fitted = True
        
    def predict(self, features: list) -> Tuple[float, RiskLevel]:
        if not self.is_fitted:
            raise NotFittedError("Model is not fitted yet.")
            
        if len(features) != len(FEATURE_NAMES):
            raise ValueError(f"Expected {len(FEATURE_NAMES)} features, got {len(features)}")
            
        for val in features:
            if not isinstance(val, (int, float)):
                raise ValueError("All features must be numeric")
                
        # Predict score
        X = np.array([features])
        pred_score_raw = self.model.predict(X)[0]
        
        # Clamp to [0, 100]
        pred_score = max(0.0, min(100.0, pred_score_raw))
        
        # Derive level exactly as Step 8
        pred_level = determine_risk_level(pred_score)
        
        return pred_score, pred_level
        
    def get_feature_importance(self) -> Dict[str, float]:
        if not self.is_fitted:
            raise NotFittedError("Model is not fitted yet.")
        importances = self.model.feature_importances_
        return dict(zip(FEATURE_NAMES, importances))
        
    def save(self, filepath: str):
        if not self.is_fitted:
            raise NotFittedError("Cannot save an unfitted model.")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "feature_names": FEATURE_NAMES
        }, filepath)
        
    @classmethod
    def load(cls, filepath: str) -> "MLRiskPredictor":
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        data = joblib.load(filepath)
        if data["feature_names"] != FEATURE_NAMES:
            raise ValueError("Loaded model feature schema does not match current schema.")
            
        instance = cls()
        instance.model = data["model"]
        instance.is_fitted = True
        return instance
