import pandas as pd
import random
from typing import List, Dict, Any, Tuple
from sklearn.model_selection import train_test_split

from src.security.environment.manager import EnvironmentManager
from src.security.environment.models import (
    DeviceContext, CoreContext, EdgeContext, SecurityMode, AuthStatus, OperationalState, EnvironmentEventType
)
from src.security.risk.manager import RiskManager
from src.security.ml_risk.features import extract_features, FEATURE_NAMES

def generate_synthetic_dataset(n_samples: int = 5000, seed: int = 42) -> pd.DataFrame:
    random.seed(seed)
    
    rows = []
    
    env = EnvironmentManager()
    risk_mgr = RiskManager(env)
    env.register_core(CoreContext("core_0", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID]))
    env.register_edge(EdgeContext("edge_0", OperationalState.ONLINE, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], "core_0"))
    
    for i in range(n_samples):
        dev_id = f"dev_{i}"
        ctx_id = f"ctx_{i}"
        
        op_state = random.choices(
            [OperationalState.ONLINE, OperationalState.DEGRADED, OperationalState.OFFLINE, OperationalState.COMPROMISED],
            weights=[0.6, 0.2, 0.1, 0.1]
        )[0]
        
        sec_mode = random.choice([SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID])
        auth_status = random.choice([AuthStatus.UNAUTHENTICATED, AuthStatus.AUTHENTICATING, AuthStatus.AUTHENTICATED])
        
        # Rules: encryption requires session. Session usually happens after auth.
        # But we can allow session without auth if environment allows, but encryption requires session.
        enc_active = random.choice([True, False])
        if enc_active:
            session_id = f"ses_{i}"
        else:
            session_id = f"ses_{i}" if random.random() > 0.3 else None
            
        auth_failures = random.choices([0, 1, 2, 3, 5], weights=[0.5, 0.2, 0.15, 0.1, 0.05])[0]
        extra_telemetry = random.randint(0, 10)
        
        env.register_device(DeviceContext(dev_id, "ue", op_state, [SecurityMode.CLASSICAL, SecurityMode.PQC, SecurityMode.HYBRID], ["ed25519"], ["mldsa"], "edge_0"))
        
        env.create_communication_context(ctx_id, dev_id, "core_0", sec_mode)
        
        # State transitions
        if auth_status in [AuthStatus.AUTHENTICATING, AuthStatus.AUTHENTICATED]:
            env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATING)
            
        if auth_status == AuthStatus.AUTHENTICATED:
            if session_id and enc_active:
                env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, session_id=session_id, encryption_active=True)
            elif session_id:
                env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED, session_id=session_id)
            else:
                env.update_security_context(ctx_id, auth_status=AuthStatus.AUTHENTICATED)
        else:
            # Not authenticated, so don't set encryption to True because that requires authenticated usually in 6G, but environment only requires session.
            # But let's just do valid states
            if session_id and enc_active:
                env.update_security_context(ctx_id, session_id=session_id, encryption_active=True)
            elif session_id:
                env.update_security_context(ctx_id, session_id=session_id)
                
        # Populate telemetry
        for _ in range(auth_failures):
            env.telemetry.record(env.current_tick, EnvironmentEventType.AUTHENTICATION_FAILED.value, ctx_id, dev_id, {})
        for _ in range(extra_telemetry):
            env.telemetry.record(env.current_tick, EnvironmentEventType.CONTEXT_UPDATED.value, ctx_id, dev_id, {})
            
        features = extract_features(env, ctx_id)
        ctx_risk = risk_mgr.evaluate_context(ctx_id)
        ent_risk = risk_mgr.evaluate_entity(dev_id)
        
        ref_score = min(100.0, ctx_risk.risk_score + ent_risk.risk_score)
        from src.security.risk.scorer import determine_risk_level
        ref_level = determine_risk_level(ref_score).value
        
        row = [f"sample_{i}"] + features + [ref_score, ref_level]
        rows.append(row)
        
    columns = ["sample_id"] + FEATURE_NAMES + ["reference_risk_score", "reference_risk_level"]
    df = pd.DataFrame(rows, columns=columns)
    return df

def split_dataset(df: pd.DataFrame, seed: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    n = len(df)
    n_test = int(n * 0.15)
    n_val = int(n * 0.15)
    train_val, test = train_test_split(df, test_size=n_test, random_state=seed)
    train, val = train_test_split(train_val, test_size=n_val, random_state=seed)
    return train, val, test

def split_dataset_grouped(df: pd.DataFrame, seed: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    unique_states = df.drop_duplicates(subset=FEATURE_NAMES).copy()
    n = len(unique_states)
    n_test = int(n * 0.15)
    n_val = int(n * 0.15)
    
    train_val_states, test_states = train_test_split(unique_states, test_size=n_test, random_state=seed)
    train_states, val_states = train_test_split(train_val_states, test_size=n_val, random_state=seed)
    
    train = df.merge(train_states[FEATURE_NAMES], on=FEATURE_NAMES, how='inner')
    val = df.merge(val_states[FEATURE_NAMES], on=FEATURE_NAMES, how='inner')
    test = df.merge(test_states[FEATURE_NAMES], on=FEATURE_NAMES, how='inner')
    
    return train, val, test
