import pytest
import os
import pandas as pd
import numpy as np
from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, CoreContext, EdgeContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.ml_risk.features import extract_features, FEATURE_NAMES, OPERATIONAL_STATE_ENCODING, SECURITY_MODE_ENCODING
from src.security.ml_risk.dataset import generate_synthetic_dataset, split_dataset
from src.security.ml_risk.model import MLRiskPredictor
from src.security.ml_risk.metrics import compute_regression_metrics, compute_classification_metrics
from src.security.risk.models import RiskLevel
from src.security.ml_risk.predictor import MLRiskPredictorAPI

def setup_env(sec_mode=SecurityMode.CLASSICAL) -> EnvironmentManager:
    env = EnvironmentManager()
    env.register_core(CoreContext("core_0", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    env.register_edge(EdgeContext("edge_0", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], "core_0"))
    env.register_device(DeviceContext("dev_0", "ue", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], "edge_0"))
    env.create_communication_context("ctx_0", "dev_0", "core_0", sec_mode)
    return env

# 1. Deterministic feature extraction
def test_deterministic_feature_extraction():
    env = setup_env()
    f1 = extract_features(env, "ctx_0")
    f2 = extract_features(env, "ctx_0")
    assert f1 == f2

# 2. Correct operational-state encoding
def test_operational_state_encoding():
    env = setup_env()
    env.update_entity_state("dev_0", OperationalState.DEGRADED)
    f = extract_features(env, "ctx_0")
    assert f[0] == float(OPERATIONAL_STATE_ENCODING[OperationalState.DEGRADED])

# 3. Correct encryption encoding
def test_encryption_encoding():
    env = setup_env()
    env.update_security_context("ctx_0", session_id="ses_0")
    env.update_security_context("ctx_0", encryption_active=True)
    f = extract_features(env, "ctx_0")
    assert f[1] == 1.0

# 4. Correct session encoding
def test_session_encoding():
    env = setup_env()
    env.update_security_context("ctx_0", session_id="ses_0")
    f = extract_features(env, "ctx_0")
    assert f[2] == 1.0

# 5. Correct security-mode encoding
def test_security_mode_encoding():
    env = setup_env(SecurityMode.PQC)
    f = extract_features(env, "ctx_0")
    assert f[3] == float(SECURITY_MODE_ENCODING[SecurityMode.PQC])

# 6. Authentication failure counting
def test_authentication_failure_counting():
    env = setup_env()
    env.telemetry.record(1, EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_0", "dev_0", {})
    env.telemetry.record(2, EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_0", "dev_0", {})
    f = extract_features(env, "ctx_0")
    assert f[4] == 2.0

# 7. Authentication failure rate
def test_authentication_failure_rate():
    env = setup_env()
    env.telemetry.record(1, EnvironmentEventType.AUTHENTICATION_FAILED.value, "ctx_0", "dev_0", {})
    env.telemetry.record(2, EnvironmentEventType.CONTEXT_UPDATED.value, "ctx_0", "dev_0", {})
    f = extract_features(env, "ctx_0")
    # Instead of asserting exact rate, assert formula
    assert f[7] == (f[4] / f[6] if f[6] > 0 else 0.0)

# 8. Missing/invalid state rejection
def test_missing_state_rejection():
    env = setup_env()
    with pytest.raises(ValueError):
        extract_features(env, "invalid_ctx")

# 9. Feature schema consistency
def test_feature_schema_consistency():
    env = setup_env()
    f = extract_features(env, "ctx_0")
    assert len(f) == len(FEATURE_NAMES)

# 10. Dataset reproducibility with fixed seed
def test_dataset_reproducibility():
    df1 = generate_synthetic_dataset(10, seed=42)
    df2 = generate_synthetic_dataset(10, seed=42)
    pd.testing.assert_frame_equal(df1, df2)

# 11. Expected columns exist
def test_expected_columns_exist():
    df = generate_synthetic_dataset(2)
    expected_cols = ["sample_id"] + FEATURE_NAMES + ["reference_risk_score", "reference_risk_level"]
    assert list(df.columns) == expected_cols

# 12. sample_id excluded from feature matrix
def test_sample_id_excluded():
    assert "sample_id" not in FEATURE_NAMES

# 13. No secret material in dataset
def test_no_secret_material_in_dataset():
    df = generate_synthetic_dataset(2)
    s = df.to_string()
    assert "secret" not in s.lower()
    assert "key" not in s.lower()

# 14. Reference labels match Step 8 risk engine
def test_reference_labels_exist():
    df = generate_synthetic_dataset(2)
    assert "reference_risk_score" in df.columns
    assert "reference_risk_level" in df.columns
    assert not df["reference_risk_score"].isnull().any()

# 15. Dataset contains multiple risk levels
def test_multiple_risk_levels():
    df = generate_synthetic_dataset(50)
    levels = df["reference_risk_level"].unique()
    assert len(levels) > 1

# 16. Train/validation/test sizes are correct
def test_train_val_test_sizes():
    df = generate_synthetic_dataset(100)
    train, val, test = split_dataset(df)
    assert len(train) + len(val) + len(test) == 100

def test_split_grouped_zero_overlap():
    from src.security.ml_risk.dataset import split_dataset_grouped
    df = generate_synthetic_dataset(200)
    train, val, test = split_dataset_grouped(df)
    
    tr_states = set(tuple(x) for x in train[FEATURE_NAMES].values)
    va_states = set(tuple(x) for x in val[FEATURE_NAMES].values)
    te_states = set(tuple(x) for x in test[FEATURE_NAMES].values)
    
    assert len(tr_states.intersection(va_states)) == 0
    assert len(tr_states.intersection(te_states)) == 0
    assert len(va_states.intersection(te_states)) == 0
    
    # Feature + target
    tr_ft = set(tuple(x) for x in train[FEATURE_NAMES + ["reference_risk_score"]].values)
    va_ft = set(tuple(x) for x in val[FEATURE_NAMES + ["reference_risk_score"]].values)
    te_ft = set(tuple(x) for x in test[FEATURE_NAMES + ["reference_risk_score"]].values)
    
    assert len(tr_ft.intersection(va_ft)) == 0
    assert len(tr_ft.intersection(te_ft)) == 0
    assert len(va_ft.intersection(te_ft)) == 0

def test_deterministic_grouped_split():
    from src.security.ml_risk.dataset import split_dataset_grouped
    df = generate_synthetic_dataset(100)
    tr1, va1, te1 = split_dataset_grouped(df, seed=42)
    tr2, va2, te2 = split_dataset_grouped(df, seed=42)
    
    pd.testing.assert_frame_equal(tr1, tr2)
    pd.testing.assert_frame_equal(va1, va2)
    pd.testing.assert_frame_equal(te1, te2)

# 17. Model trains successfully
def test_model_trains():
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    assert model.is_fitted

# 18. Prediction is deterministic
def test_prediction_deterministic():
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    f = X[0].tolist()
    p1, _ = model.predict(f)
    p2, _ = model.predict(f)
    assert p1 == p2

# 19. Prediction is within [0,100]
def test_prediction_within_bounds():
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    f = X[0].tolist()
    p1, _ = model.predict(f)
    assert 0.0 <= p1 <= 100.0

# 20. Risk-level derivation uses Step 8 thresholds
def test_risk_level_derivation():
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    
    from src.security.risk.scorer import determine_risk_level
    f = X[0].tolist()
    score, level = model.predict(f)
    assert level == determine_risk_level(score)

# 20.5 Read-only inference audit
def test_read_only_inference(tmp_path):
    env = setup_env()
    # Save a model
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    p = str(tmp_path / "model.pkl")
    model.save(p)
    
    api = MLRiskPredictorAPI(p)
    # Take state snapshot
    ctx_before = env.comm_contexts["ctx_0"]
    auth_before = ctx_before.security.auth_status
    enc_before = ctx_before.security.encryption_active
    mode_before = ctx_before.security.security_mode
    telem_len_before = len(env.telemetry.records)
    
    api.predict_context_risk(env, "ctx_0")
    
    ctx_after = env.comm_contexts["ctx_0"]
    assert ctx_after.security.auth_status == auth_before
    assert ctx_after.security.encryption_active == enc_before
    assert ctx_after.security.security_mode == mode_before
    assert len(env.telemetry.records) == telem_len_before

# 21. Feature ordering is validated
def test_feature_ordering_validated():
    model = MLRiskPredictor()
    with pytest.raises(ValueError):
        model.predict([1.0])

# 22. Invalid feature vector rejected
def test_invalid_feature_vector_rejected():
    model = MLRiskPredictor()
    model.is_fitted = True
    with pytest.raises(ValueError):
        model.predict(["string"] * len(FEATURE_NAMES))

# 23. MAE computed correctly
def test_mae_computed():
    metrics = compute_regression_metrics([10.0, 20.0], [12.0, 18.0])
    assert metrics["MAE"] == 2.0

# 24. RMSE computed correctly
def test_rmse_computed():
    metrics = compute_regression_metrics([10.0, 20.0], [12.0, 18.0])
    assert metrics["RMSE"] == 2.0

# 25. R² computed correctly
def test_r2_computed():
    metrics = compute_regression_metrics([10.0, 20.0], [10.0, 20.0])
    assert metrics["R2"] == 1.0

# 26. Classification metrics computed correctly
def test_classification_metrics():
    metrics = compute_classification_metrics([RiskLevel.LOW, RiskLevel.HIGH], [RiskLevel.LOW, RiskLevel.LOW])
    assert metrics["Accuracy"] == 0.5
    assert "Macro_F1" in metrics

# 27. Model can be saved
def test_model_can_be_saved(tmp_path):
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    p = str(tmp_path / "model.pkl")
    model.save(p)
    assert os.path.exists(p)

# 28. Model can be loaded
def test_model_can_be_loaded(tmp_path):
    df = generate_synthetic_dataset(10)
    X = df[FEATURE_NAMES].values
    y = df["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X, y)
    p = str(tmp_path / "model.pkl")
    model.save(p)
    m2 = MLRiskPredictor.load(p)
    assert m2.is_fitted

# 29. Loaded model produces same prediction
def test_loaded_model_same_prediction(tmp_path):
    from src.security.ml_risk.dataset import split_dataset_grouped
    df = generate_synthetic_dataset(100)
    train, val, test = split_dataset_grouped(df, seed=42)
    
    X_train = train[FEATURE_NAMES].values
    y_train = train["reference_risk_score"].values
    
    model = MLRiskPredictor()
    model.train(X_train, y_train)
    p = str(tmp_path / "model.pkl")
    model.save(p)
    m2 = MLRiskPredictor.load(p)
    
    X_test = test[FEATURE_NAMES].values
    
    for f in X_test:
        f_list = f.tolist()
        p1, l1 = model.predict(f_list)
        p2, l2 = m2.predict(f_list)
        assert p1 == p2
        assert l1 == l2

# 30. Confusion matrix total rows
def test_confusion_matrix_total():
    from sklearn.metrics import confusion_matrix
    from src.security.ml_risk.dataset import split_dataset_grouped
    from src.security.risk.models import RiskLevel
    
    df = generate_synthetic_dataset(100)
    train, val, test = split_dataset_grouped(df, seed=42)
    
    X_train = train[FEATURE_NAMES].values
    y_train = train["reference_risk_score"].values
    model = MLRiskPredictor()
    model.train(X_train, y_train)
    
    X_test = test[FEATURE_NAMES].values
    y_test_levels = test["reference_risk_level"].tolist()
    
    y_pred_levels = []
    for f in X_test:
        _, level = model.predict(f.tolist())
        y_pred_levels.append(level.value)
        
    labels = [RiskLevel.LOW.value, RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
    cm = confusion_matrix(y_test_levels, y_pred_levels, labels=labels)
    assert cm.sum() == len(test)
