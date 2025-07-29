import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

df = pd.read_csv("logs/connection_log.csv")

features = ['num_requests', 'avg_interval', 'filename_entropy']
X = df[features]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

clf = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
clf.fit(X_scaled)

import os

os.makedirs("model", exist_ok=True)

joblib.dump(clf, "model/isolation_forest.pkl")
joblib.dump(scaler, "model/scaler.pkl")

df['prediction'] = clf.predict(X_scaled)
df['prediction_label'] = df['prediction'].apply(lambda x: 1 if x == -1 else 0)
print(df[['ip', 'username', 'prediction_label', 'is_fake_session']])
