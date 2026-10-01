import numpy as np
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score, accuracy_score, f1_score
from typing import Dict, Any, List

from src.security.risk.models import RiskLevel

def compute_regression_metrics(y_true: List[float], y_pred: List[float]) -> Dict[str, float]:
    if len(y_true) == 0 or len(y_pred) == 0:
        return {"MAE": 0.0, "RMSE": 0.0, "R2": 0.0}
    return {
        "MAE": mean_absolute_error(y_true, y_pred),
        "RMSE": float(np.sqrt(mean_squared_error(y_true, y_pred))),
        "R2": r2_score(y_true, y_pred)
    }

def compute_classification_metrics(y_true_levels: List[RiskLevel], y_pred_levels: List[RiskLevel]) -> Dict[str, float]:
    if len(y_true_levels) == 0 or len(y_pred_levels) == 0:
        return {"Accuracy": 0.0, "Macro_F1": 0.0}
        
    y_true_str = [lvl.value for lvl in y_true_levels]
    y_pred_str = [lvl.value for lvl in y_pred_levels]
    
    return {
        "Accuracy": accuracy_score(y_true_str, y_pred_str),
        "Macro_F1": f1_score(y_true_str, y_pred_str, average="macro", zero_division=0)
    }
