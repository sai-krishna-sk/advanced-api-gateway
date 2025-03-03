import os
import pickle
import numpy as np
from flask import request
from sklearn.ensemble import IsolationForest

MODEL_PATH = 'ml_model.pkl'

def load_model():
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
    except FileNotFoundError:
        # Train a basic IsolationForest model on synthetic data
        X_train = np.random.rand(100, 3)  # 100 samples, 3 features
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X_train)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(model, f)
    return model

model = load_model()

def extract_features(req):
    # Extract features: body length, total number of parameters, and header count
    body = req.get_data(as_text=True)
    body_length = len(body)
    num_params = len(req.args) + len(req.form)
    num_headers = len(req.headers)
    return np.array([[body_length, num_params, num_headers]])

def ml_anomaly_detection():
    features = extract_features(request)
    prediction = model.predict(features)  # 1 for normal, -1 for anomaly
    request.anomaly_score = 0 if prediction[0] == 1 else 1
    if prediction[0] == -1:
        print(f"Anomaly detected with features: {features}")

