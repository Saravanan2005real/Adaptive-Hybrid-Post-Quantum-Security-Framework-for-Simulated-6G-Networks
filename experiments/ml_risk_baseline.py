import os
import pandas as pd
from typing import Tuple

from src.security.ml_risk.dataset import generate_synthetic_dataset, split_dataset, split_dataset_grouped
from src.security.ml_risk.model import MLRiskPredictor
from src.security.ml_risk.features import FEATURE_NAMES
from src.security.ml_risk.metrics import compute_regression_metrics, compute_classification_metrics
from src.security.risk.scorer import determine_risk_level

def calculate_overlap(df1: pd.DataFrame, df2: pd.DataFrame, cols) -> int:
    overlap = df1[cols].merge(df2[cols].drop_duplicates(), on=cols, how='inner')
    return len(overlap)

def run_experiment(df: pd.DataFrame, train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame, experiment_name: str) -> dict:
    print(f"\n==================================================")
    print(f"EXPERIMENT: {experiment_name}")
    print(f"==================================================")
    
    unique_train = len(train.drop_duplicates(subset=FEATURE_NAMES))
    unique_val = len(val.drop_duplicates(subset=FEATURE_NAMES))
    unique_test = len(test.drop_duplicates(subset=FEATURE_NAMES))
    
    print("\nSplit Sizes:")
    print(f"Unique states: Train={unique_train}, Val={unique_val}, Test={unique_test}")
    print(f"Rows: Train={len(train)}, Val={len(val)}, Test={len(test)}")
    
    overlap_train_test = calculate_overlap(test, train, FEATURE_NAMES)
    overlap_train_val = calculate_overlap(val, train, FEATURE_NAMES)
    overlap_val_test = calculate_overlap(test, val, FEATURE_NAMES)
    
    print("\nFeature Overlap:")
    print(f"Train/Test overlap: {overlap_train_test}")
    print(f"Train/Val overlap: {overlap_train_val}")
    print(f"Val/Test overlap: {overlap_val_test}")
    
    X_train = train[FEATURE_NAMES].values
    y_train = train["reference_risk_score"].values
    
    model = MLRiskPredictor()
    model.train(X_train, y_train)
    
    X_test = test[FEATURE_NAMES].values
    y_test = test["reference_risk_score"].values
    y_test_levels = test["reference_risk_level"].tolist()
    
    y_pred_scores = []
    y_pred_levels = []
    
    for f in X_test:
        score, level = model.predict(f.tolist())
        y_pred_scores.append(score)
        y_pred_levels.append(level)
        
    reg_metrics = compute_regression_metrics(y_test, y_pred_scores)
    
    from src.security.risk.models import RiskLevel
    y_test_enum = [RiskLevel(l) for l in y_test_levels]
    cls_metrics = compute_classification_metrics(y_test_enum, y_pred_levels)
    
    print("\nEvaluating on Test Set...")
    print(f"Regression Metrics: MAE={reg_metrics['MAE']:.4f}, RMSE={reg_metrics['RMSE']:.4f}, R2={reg_metrics['R2']:.9f}")
    print(f"Classification Metrics: Accuracy={cls_metrics['Accuracy']:.4f}, Macro F1={cls_metrics['Macro_F1']:.4f}")
    
    # Target counts
    from collections import Counter
    test_level_counts = Counter(y_test_levels)
    pred_level_counts = Counter([lvl.value for lvl in y_pred_levels])
    
    print("\nTest Target Distribution (True / Predicted):")
    from src.security.risk.models import RiskLevel
    for lvl in [RiskLevel.LOW.value, RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]:
        print(f"  {lvl}: {test_level_counts.get(lvl, 0)} / {pred_level_counts.get(lvl, 0)}")
        
    print("\nConfusion Matrix (Rows=True, Cols=Predicted):")
    from sklearn.metrics import confusion_matrix
    labels = [RiskLevel.LOW.value, RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
    cm = confusion_matrix(y_test_levels, [lvl.value for lvl in y_pred_levels], labels=labels)
    
    # Print formatted matrix
    print(f"{'':<12} " + " ".join([f"{l[:4]:>8}" for l in labels]))
    for i, true_label in enumerate(labels):
        row_str = " ".join([f"{cm[i][j]:>8}" for j in range(len(labels))])
        print(f"{true_label:<12} {row_str}")
    
    return {
        "train_rows": len(train),
        "val_rows": len(val),
        "test_rows": len(test),
        "unique_train": unique_train,
        "unique_val": unique_val,
        "unique_test": unique_test,
        "overlap_train_test": overlap_train_test,
        "MAE": reg_metrics["MAE"],
        "RMSE": reg_metrics["RMSE"],
        "R2": reg_metrics["R2"],
        "Accuracy": cls_metrics["Accuracy"],
        "Macro_F1": cls_metrics["Macro_F1"],
        "model": model
    }

def main():
    print("Starting AERIS-PQ6G ML Risk Prediction Baseline...\n")
    df = generate_synthetic_dataset(5000, seed=42)
    print(f"Dataset Dimensions: {len(df)} rows, {len(df.columns)} columns\n")
    
    feature_df = df[FEATURE_NAMES]
    unique_features = feature_df.drop_duplicates()
    print(f"Total Unique Feature Vectors in Dataset: {len(unique_features)}")
    
    # Experiment 1: Repeated-State / Random Row Split
    train_1, val_1, test_1 = split_dataset(df, seed=42)
    res_1 = run_experiment(df, train_1, val_1, test_1, "Repeated-State Random Row Split")
    
    # Experiment 2: State-Independent Grouped Split
    train_2, val_2, test_2 = split_dataset_grouped(df, seed=42)
    res_2 = run_experiment(df, train_2, val_2, test_2, "State-Independent Grouped Split")
    
    print("\n==================================================")
    print("COMPARE BOTH EXPERIMENTS")
    print("==================================================")
    print(f"{'Metric':<25} | {'Exp 1: Random Row':<20} | {'Exp 2: Grouped'}")
    print("-" * 70)
    for k in ["train_rows", "val_rows", "test_rows", "unique_train", "unique_val", "unique_test", "overlap_train_test", "MAE", "RMSE", "R2", "Accuracy", "Macro_F1"]:
        v1 = res_1[k]
        v2 = res_2[k]
        if isinstance(v1, float):
            print(f"{k:<25} | {v1:<20.4f} | {v2:.4f}")
        else:
            print(f"{k:<25} | {v1:<20} | {v2}")
            
    print("\nInterpretation:")
    print("The random row split measures approximation of the deterministic Step 8 mapping when repeated security states occur across partitions, whereas the grouped split evaluates prediction on feature-vector configurations that were not present in the training partition.")
    
    print("\nGrouped Model Feature Importance:")
    print("Random Forest model-specific feature importance; not causal importance.")
    model = res_2["model"]
    importances = model.model.feature_importances_
    for name, imp in zip(FEATURE_NAMES, importances):
        print(f"  {name}: {imp:.4f}")

if __name__ == "__main__":
    main()
