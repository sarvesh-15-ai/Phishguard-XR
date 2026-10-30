"""
train.py — PhishGuard Phase 4

Trains the full PhishGuardModel (transformer + structural + attention
fusion) on your real dataset, and also trains classical baselines
(Logistic Regression, Random Forest) on the lexical features so you have
a genuine comparison table for your IEEE paper — no more placeholder
numbers.

Run this from your project root:
    python3 src/training/train.py

Expects (from Phases 1-3):
    data/phishguard_dataset.csv
    data/processed/lexical_features.csv
    data/processed/tokenized.pt
    src/models/{transformer_branch,structural_branch,fusion_classifier}.py

Outputs:
    outputs/best_model.pt          - best PhishGuardModel checkpoint
    outputs/lexical_scaler.joblib  - fitted StandardScaler (needed at inference time)
    outputs/results_table.csv      - accuracy/precision/recall/F1 for all models
    outputs/training_log.csv       - per-epoch train/val metrics
"""

import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Make src/models importable
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "models"))
from fusion_classifier import PhishGuardModel  # noqa: E402

DATA_DIR = "data"
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
OUTPUT_DIR = "outputs"

LEXICAL_PATH = os.path.join(PROCESSED_DIR, "lexical_features.csv")
TOKENIZED_PATH = os.path.join(PROCESSED_DIR, "tokenized.pt")

BATCH_SIZE = 32
NUM_EPOCHS = 3
PATIENCE = 2  # early stopping: stop if val F1 doesn't improve for this many epochs
TRANSFORMER_LR = 2e-5
HEAD_LR = 1e-3
RANDOM_STATE = 42

LEXICAL_FEATURE_COLS = [
    "url_length", "num_dots", "num_hyphens", "num_digits", "num_subdomains",
    "has_ip_host", "has_at_symbol", "has_https", "suspicious_tld",
    "domain_entropy", "path_length", "num_query_params",
]


def get_device():
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


class PhishGuardDataset(Dataset):
    def __init__(self, input_ids, attention_mask, lexical_features, labels):
        self.input_ids = input_ids
        self.attention_mask = attention_mask
        self.lexical_features = lexical_features
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            "input_ids": self.input_ids[idx],
            "attention_mask": self.attention_mask[idx],
            "lexical_features": self.lexical_features[idx],
            "label": self.labels[idx],
        }


def load_data():
    print("[step] Loading processed data...")
    lexical_df = pd.read_csv(LEXICAL_PATH)
    tokenized = torch.load(TOKENIZED_PATH)

    assert len(lexical_df) == len(tokenized["labels"]), (
        "Row count mismatch between lexical_features.csv and tokenized.pt — "
        "did you re-run extract_features.py on a different dataset size "
        "without regenerating both outputs together?"
    )
    # Sanity check: labels should match between the two files, row for row
    lexical_labels = lexical_df["label"].values
    tokenized_labels = tokenized["labels"].numpy()
    assert np.array_equal(lexical_labels, tokenized_labels), (
        "Label mismatch between lexical_features.csv and tokenized.pt — "
        "the two files are out of sync. Re-run extract_features.py."
    )

    print(f"[ok] Loaded {len(lexical_df)} samples")
    return lexical_df, tokenized


def split_indices(labels: np.ndarray):
    idx = np.arange(len(labels))
    train_idx, temp_idx = train_test_split(
        idx, test_size=0.3, stratify=labels, random_state=RANDOM_STATE
    )
    val_idx, test_idx = train_test_split(
        temp_idx, test_size=0.5, stratify=labels[temp_idx], random_state=RANDOM_STATE
    )
    print(f"[split] train={len(train_idx)}  val={len(val_idx)}  test={len(test_idx)}")
    return train_idx, val_idx, test_idx


def compute_metrics(y_true, y_pred):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }


def train_baselines(lexical_df, train_idx, test_idx, scaler):
    print("\n[step] Training baseline models (Logistic Regression, Random Forest)...")
    X = lexical_df[LEXICAL_FEATURE_COLS].values
    y = lexical_df["label"].values

    X_train = scaler.transform(X[train_idx])
    X_test = scaler.transform(X[test_idx])
    y_train, y_test = y[train_idx], y[test_idx]

    results = {}

    lr = LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)
    lr.fit(X_train, y_train)
    results["Logistic Regression"] = compute_metrics(y_test, lr.predict(X_test))
    print(f"[ok] Logistic Regression: {results['Logistic Regression']}")

    rf = RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1)
    rf.fit(X_train, y_train)
    results["Random Forest"] = compute_metrics(y_test, rf.predict(X_test))
    print(f"[ok] Random Forest: {results['Random Forest']}")

    try:
        from xgboost import XGBClassifier
        xgb = XGBClassifier(random_state=RANDOM_STATE, eval_metric="logloss")
        xgb.fit(X_train, y_train)
        results["XGBoost"] = compute_metrics(y_test, xgb.predict(X_test))
        print(f"[ok] XGBoost: {results['XGBoost']}")
    except ImportError:
        print("[skip] xgboost not installed — skipping (pip install xgboost --break-system-packages to add it)")

    return results


def run_epoch(model, loader, device, optimizer=None, loss_fn=None):
    is_train = optimizer is not None
    model.train() if is_train else model.eval()

    total_loss = 0.0
    all_preds, all_labels = [], []

    context = torch.enable_grad() if is_train else torch.no_grad()
    with context:
        for step, batch in enumerate(loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            lexical_features = batch["lexical_features"].to(device)
            labels = batch["label"].to(device).float()

            logits = model(input_ids, attention_mask, lexical_features)
            loss = loss_fn(logits, labels)

            if is_train:
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

            total_loss += loss.item()
            preds = (torch.sigmoid(logits) >= 0.5).long().cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(labels.long().cpu().numpy())

            if is_train and step % 200 == 0:
                print(f"    [batch {step}/{len(loader)}] loss={loss.item():.4f}")

    avg_loss = total_loss / len(loader)
    metrics = compute_metrics(all_labels, all_preds)
    return avg_loss, metrics


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    device = get_device()
    print(f"[ok] Using device: {device}")

    lexical_df, tokenized = load_data()
    labels = lexical_df["label"].values

    train_idx, val_idx, test_idx = split_indices(labels)

    # Fit the scaler ONLY on training data to avoid leaking test-set
    # statistics into the model (a common but subtle correctness bug)
    scaler = StandardScaler()
    scaler.fit(lexical_df.loc[train_idx, LEXICAL_FEATURE_COLS].values)
    joblib.dump(scaler, os.path.join(OUTPUT_DIR, "lexical_scaler.joblib"))
    print("[ok] Fitted and saved lexical feature scaler")

    all_lexical_scaled = scaler.transform(lexical_df[LEXICAL_FEATURE_COLS].values)
    lexical_tensor = torch.tensor(all_lexical_scaled, dtype=torch.float32)
    labels_tensor = torch.tensor(labels, dtype=torch.long)

    def make_loader(idx, shuffle):
        subset = PhishGuardDataset(
            tokenized["input_ids"][idx],
            tokenized["attention_mask"][idx],
            lexical_tensor[idx],
            labels_tensor[idx],
        )
        return DataLoader(subset, batch_size=BATCH_SIZE, shuffle=shuffle)

    train_loader = make_loader(train_idx, shuffle=True)
    val_loader = make_loader(val_idx, shuffle=False)
    test_loader = make_loader(test_idx, shuffle=False)

    model = PhishGuardModel(embed_dim=128).to(device)

    # Different learning rates for the pretrained transformer vs the
    # freshly-initialized heads — standard fine-tuning practice, since the
    # pretrained weights need gentler updates than the new layers.
    optimizer = torch.optim.AdamW([
        {"params": model.transformer_branch.encoder.parameters(), "lr": TRANSFORMER_LR},
        {"params": model.transformer_branch.projection.parameters(), "lr": HEAD_LR},
        {"params": model.structural_branch.parameters(), "lr": HEAD_LR},
        {"params": model.fusion.parameters(), "lr": HEAD_LR},
        {"params": model.classifier.parameters(), "lr": HEAD_LR},
    ])
    loss_fn = nn.BCEWithLogitsLoss()

    best_val_f1 = -1.0
    epochs_without_improvement = 0
    training_log = []

    print(f"\n[step] Starting training for up to {NUM_EPOCHS} epochs...")
    for epoch in range(1, NUM_EPOCHS + 1):
        start = time.time()
        train_loss, train_metrics = run_epoch(model, train_loader, device, optimizer, loss_fn)
        val_loss, val_metrics = run_epoch(model, val_loader, device, optimizer=None, loss_fn=loss_fn)
        elapsed = time.time() - start

        print(
            f"[epoch {epoch}/{NUM_EPOCHS}] "
            f"train_loss={train_loss:.4f} train_f1={train_metrics['f1']:.4f} | "
            f"val_loss={val_loss:.4f} val_f1={val_metrics['f1']:.4f} "
            f"({elapsed:.1f}s)"
        )

        training_log.append({
            "epoch": epoch, "train_loss": train_loss, "val_loss": val_loss,
            **{f"train_{k}": v for k, v in train_metrics.items()},
            **{f"val_{k}": v for k, v in val_metrics.items()},
        })

        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            epochs_without_improvement = 0
            torch.save(model.state_dict(), os.path.join(OUTPUT_DIR, "best_model.pt"))
            print(f"    [ok] New best model saved (val_f1={best_val_f1:.4f})")
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= PATIENCE:
                print(f"    [stop] No improvement for {PATIENCE} epochs — early stopping.")
                break

    pd.DataFrame(training_log).to_csv(os.path.join(OUTPUT_DIR, "training_log.csv"), index=False)

    # Load the best checkpoint before final test evaluation
    model.load_state_dict(torch.load(os.path.join(OUTPUT_DIR, "best_model.pt"), map_location=device))
    test_loss, test_metrics = run_epoch(model, test_loader, device, optimizer=None, loss_fn=loss_fn)
    print(f"\n[result] PhishGuard (full model) test metrics: {test_metrics}")

    baseline_results = train_baselines(lexical_df, train_idx, test_idx, scaler)

    all_results = {"PhishGuard (Transformer+Structural+Attention Fusion)": test_metrics, **baseline_results}
    results_df = pd.DataFrame(all_results).T
    results_df.to_csv(os.path.join(OUTPUT_DIR, "results_table.csv"))

    print("\n=== FINAL RESULTS TABLE ===")
    print(results_df.round(4).to_string())
    print(f"\nSaved to {OUTPUT_DIR}/results_table.csv — use this in your IEEE paper's Results section.")


if __name__ == "__main__":
    main()