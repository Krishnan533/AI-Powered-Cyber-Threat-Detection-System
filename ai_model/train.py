import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def generate_sample_dataset(filepath):
    """Generates synthetic network traffic to train the Isolation Forest model."""
    print("Generating synthetic network traffic dataset...")
    np.random.seed(42)
    
    # 1. Normal traffic profile: small/medium size packets, common ports, quick intervals
    n_normal = 2000
    normal_data = {
        'packet_size': np.random.normal(loc=120, scale=80, size=n_normal).astype(int),
        'protocol_numeric': np.random.choice([6, 17, 1], p=[0.7, 0.25, 0.05], size=n_normal), # TCP, UDP, ICMP
        'src_port': np.random.choice([80, 443, 53, 123, 53210, 49152], size=n_normal),
        'dst_port': np.random.choice([80, 443, 53, 123, 8080], size=n_normal),
        'time_delta': np.random.exponential(scale=0.1, size=n_normal) # frequent, small delta
    }
    df_normal = pd.DataFrame(normal_data)
    df_normal['packet_size'] = df_normal['packet_size'].clip(lower=40)
    df_normal['label'] = 1  # 1 for inliers (normal)

    # 2. Anomalous traffic profile: Port scanning, volumetric (DDoS), large exfiltration, abnormal ports
    n_anomalous = 150
    
    # DDoS (high density, uniform large size or uniform small size)
    n_ddos = 50
    ddos_data = {
        'packet_size': np.random.normal(loc=1400, scale=50, size=n_ddos).astype(int),
        'protocol_numeric': np.ones(n_ddos, dtype=int) * 17, # UDP flood
        'src_port': np.random.randint(1024, 65535, size=n_ddos),
        'dst_port': np.ones(n_ddos, dtype=int) * 80,
        'time_delta': np.random.exponential(scale=0.0001, size=n_ddos) # extremely small delta
    }
    
    # Port scan (many destination ports, quick sequence)
    n_scan = 50
    scan_data = {
        'packet_size': np.random.randint(40, 60, size=n_scan),
        'protocol_numeric': np.ones(n_scan, dtype=int) * 6, # TCP SYN
        'src_port': np.random.randint(30000, 60000, size=n_scan),
        'dst_port': np.arange(1, n_scan + 1), # incrementing destination ports
        'time_delta': np.random.exponential(scale=0.001, size=n_scan)
    }
    
    # Exfiltration (very large size, unusual destination port)
    n_exfil = 50
    exfil_data = {
        'packet_size': np.random.normal(loc=1500, scale=10, size=n_exfil).astype(int),
        'protocol_numeric': np.ones(n_exfil, dtype=int) * 6,
        'src_port': np.ones(n_exfil, dtype=int) * 443,
        'dst_port': np.random.choice([9999, 8888, 6666], size=n_exfil),
        'time_delta': np.random.exponential(scale=0.5, size=n_exfil)
    }
    
    df_ddos = pd.DataFrame(ddos_data)
    df_scan = pd.DataFrame(scan_data)
    df_exfil = pd.DataFrame(exfil_data)
    
    df_anomaly = pd.concat([df_ddos, df_scan, df_exfil], ignore_index=True)
    df_anomaly['label'] = -1  # -1 for outliers (anomaly)
    
    # Merge and shuffle
    df = pd.concat([df_normal, df_anomaly], ignore_index=True)
    df = df.sample(frac=1).reset_index(drop=True)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    df.to_csv(filepath, index=False)
    print(f"Dataset generated and saved to {filepath}")
    return df

def train_model():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(base_dir, "dataset", "sample_traffic.csv")
    model_path = os.path.join(base_dir, "model.pkl")
    scaler_path = os.path.join(base_dir, "scaler.pkl")
    
    # Generate dataset
    df = generate_sample_dataset(dataset_path)
    
    # Prepare features
    features = ['packet_size', 'protocol_numeric', 'src_port', 'dst_port', 'time_delta']
    X = df[features].values
    y = df['label'].values
    
    # Fit StandardScaler
    print("Fitting Scaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    # contamination represents the approximate proportion of anomalies in the training set
    contamination = len(df[df['label'] == -1]) / len(df)
    print(f"Training Isolation Forest model (contamination={contamination:.4f})...")
    model = IsolationForest(
        n_estimators=150,
        max_samples='auto',
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    
    # Save parameters
    print("Saving model binaries...")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    # Evaluation
    predictions = model.predict(X_scaled)
    accuracy = np.mean(predictions == y)
    print(f"Model trained successfully. Evaluation accuracy: {accuracy:.4f}")
    
    # Print confusion details
    print(f"Normal identified as normal: {np.sum((predictions == 1) & (y == 1))}/{np.sum(y == 1)}")
    print(f"Anomalies identified as anomalies: {np.sum((predictions == -1) & (y == -1))}/{np.sum(y == -1)}")

if __name__ == "__main__":
    train_model()
