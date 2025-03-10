import os
import json
import logging
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import GridSearchCV
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import joblib
from sklearn.metrics import precision_score, recall_score, f1_score

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
DATA_PATH = "C:/Users/EFAC/PycharmProjects/NIDS/logs/extracted_features.csv"
ENCODERS_DIR = "C:/Users/EFAC/PycharmProjects/NIDS/logs/encoders"
LOGS_DIR = "C:/Users/EFAC/PycharmProjects/NIDS/logs"
SCALER_FILENAME = os.path.join(LOGS_DIR, "scaler.joblib")
FEATURES_FILENAME = os.path.join(LOGS_DIR, "feature_order.json")
MODEL_FILENAME = os.path.join(LOGS_DIR, "best_isolation_forest_model.joblib")
ANOMALIES_FILENAME = os.path.join(LOGS_DIR, "anomalies.csv")

# Create necessary directories
os.makedirs(ENCODERS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

def load_data(file_path):
    """Load dataset from a CSV file."""
    try:
        data = pd.read_csv(file_path)
        logging.info(f"Data loaded from {file_path}, shape: {data.shape}")
        return data
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise

def preprocess_data(data):
    # Retain original IPs for reference but exclude them from training
    columns_to_drop = ['Timestamp']
    data = data.drop(columns=[col for col in columns_to_drop if col in data.columns], errors='ignore')

    # Encoding categorical columns
    label_encoders = {}
    for column in data.select_dtypes(include=['object']).columns:
        encoder = LabelEncoder()
        data[column] = encoder.fit_transform(data[column])
        label_encoders[column] = encoder

        # Save encoder
        encoder_path = os.path.join(ENCODERS_DIR, f"{column}_encoder.joblib")
        joblib.dump(encoder, encoder_path)
        logging.info(f"Saved encoder for {column} to {encoder_path}")

    # Drop NA values
    data = data.dropna()

    # Save feature order
    with open(FEATURES_FILENAME, 'w') as f:
        json.dump(list(data.columns), f)
        logging.info(f"Feature order saved to {FEATURES_FILENAME}")

    return data, label_encoders

def scale_features(data):
    """Scale features using StandardScaler."""
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)
    joblib.dump(scaler, SCALER_FILENAME)
    logging.info(f"Scaler saved to {SCALER_FILENAME}")
    return data_scaled, scaler

def train_isolation_forest(X_scaled):
    """Train and tune an Isolation Forest model using GridSearchCV."""
    # Define the model and parameter grid
    isolation_forest = IsolationForest(random_state=42)
    param_grid = {
        'n_estimators': [50, 100, 150],
        'max_samples': [0.6, 0.8, 1.0],
        'contamination': [0.01, 0.05, 0.1]
    }

    # Define a custom scoring function
    def custom_score(estimator, X):
        anomaly_scores = estimator.decision_function(X)
        return np.mean(anomaly_scores)

    # Perform GridSearchCV
    grid_search = GridSearchCV(isolation_forest, param_grid, cv=3, scoring=custom_score)
    grid_search.fit(X_scaled)

    # Save the best model
    best_model = grid_search.best_estimator_
    joblib.dump(best_model, MODEL_FILENAME)
    logging.info(f"Best model saved to {MODEL_FILENAME}")

    logging.info(f"Best Parameters: {grid_search.best_params_}")
    logging.info(f"Best Custom Score: {grid_search.best_score_}")

    return best_model

def visualize_results(X, anomalies, anomaly_scores):
    """Visualize anomaly scores and detected anomalies."""
    # Anomaly score distribution
    plt.figure(figsize=(10, 6))
    sns.histplot(anomaly_scores, bins=30, kde=True, color='blue')
    plt.title("Distribution of Anomaly Scores")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Frequency")
    plt.show()

    # Anomaly scatter plot (first two features)
    plt.figure(figsize=(10, 6))
    sns.scatterplot(x=X.iloc[:, 0], y=X.iloc[:, 1], hue=anomalies, palette={1: 'blue', -1: 'red'})
    plt.title("Isolation Forest Anomaly Detection")
    plt.xlabel("Feature 1")
    plt.ylabel("Feature 2")
    plt.legend(title="Anomaly", labels=["Normal", "Anomaly"])
    plt.show()

def save_anomalies(X, anomalies):
    """Save detected anomalies to a CSV file."""
    anomaly_indices = np.where(anomalies == -1)[0]
    anomaly_data = X.iloc[anomaly_indices]
    anomaly_data.to_csv(ANOMALIES_FILENAME, index=False)
    logging.info(f"Anomalies saved to {ANOMALIES_FILENAME}, count: {len(anomaly_data)}")
    return anomaly_data

def main():
    # Load the data
    data = load_data(DATA_PATH)

    # Preprocess the data
    X, label_encoders = preprocess_data(data)

    # Scale the features
    X_scaled, scaler = scale_features(X)

    # Train the Isolation Forest
    best_model = train_isolation_forest(X_scaled)

    # Predict anomalies
    anomaly_scores = best_model.decision_function(X_scaled)
    anomalies = best_model.predict(X_scaled)

    # Visualize results
    visualize_results(X, anomalies, anomaly_scores)

    # Save anomalies
    anomaly_data = save_anomalies(X, anomalies)

    # Summary
    logging.info(f"Total anomalies detected: {len(anomaly_data)}")
    logging.info(f"Anomalies account for {len(anomaly_data) / len(X) * 100:.2f}% of the data")

if __name__ == "__main__":
    main()
