import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper


FEATURE_NAMES = [
    "ikd_ms_50_window",
    "ikd_ms_200_window",
    "ikd_ms_1s_window",
    "ikd_variance",
    "synthetic_sequence",
    "suspicious_process_launch",
    "reputation_score",
    "timing_skew_score",
]

CLASS_NAMES = ["SAFE", "SUSPICIOUS", "MALICIOUS"]


@dataclass
class TrainingArtifacts:
    weights: np.ndarray
    bias: np.ndarray
    mean: np.ndarray
    std: np.ndarray
    train_accuracy: float
    test_accuracy: float


def _seed() -> None:
    np.random.seed(42)


def generate_synthetic_dataset(samples_per_class: int = 2500) -> tuple[np.ndarray, np.ndarray]:
    _seed()

    safe = np.column_stack(
        [
            np.random.normal(105.0, 25.0, samples_per_class),
            np.random.normal(120.0, 20.0, samples_per_class),
            np.random.normal(140.0, 30.0, samples_per_class),
            np.random.normal(420.0, 120.0, samples_per_class),
            np.random.binomial(1, 0.03, samples_per_class),
            np.random.binomial(1, 0.01, samples_per_class),
            np.random.normal(30.0, 10.0, samples_per_class),
            np.random.normal(0.04, 0.02, samples_per_class),
        ]
    )

    suspicious = np.column_stack(
        [
            np.random.normal(35.0, 12.0, samples_per_class),
            np.random.normal(45.0, 14.0, samples_per_class),
            np.random.normal(60.0, 18.0, samples_per_class),
            np.random.normal(80.0, 45.0, samples_per_class),
            np.random.binomial(1, 0.35, samples_per_class),
            np.random.binomial(1, 0.20, samples_per_class),
            np.random.normal(-10.0, 12.0, samples_per_class),
            np.random.normal(0.25, 0.08, samples_per_class),
        ]
    )

    malicious = np.column_stack(
        [
            np.random.normal(8.0, 2.5, samples_per_class),
            np.random.normal(10.0, 3.0, samples_per_class),
            np.random.normal(12.0, 3.0, samples_per_class),
            np.random.normal(5.0, 4.0, samples_per_class),
            np.random.binomial(1, 0.88, samples_per_class),
            np.random.binomial(1, 0.74, samples_per_class),
            np.random.normal(-45.0, 8.0, samples_per_class),
            np.random.normal(0.70, 0.12, samples_per_class),
        ]
    )

    x = np.vstack([safe, suspicious, malicious]).astype(np.float32)
    y = np.concatenate(
        [
            np.zeros(samples_per_class, dtype=np.int64),
            np.ones(samples_per_class, dtype=np.int64),
            np.full(samples_per_class, 2, dtype=np.int64),
        ]
    )

    # Clamp physical bounds to keep synthetic values realistic.
    x[:, 0:3] = np.clip(x[:, 0:3], 1.0, 500.0)
    x[:, 3] = np.clip(x[:, 3], 0.0, 2000.0)
    x[:, 7] = np.clip(x[:, 7], 0.0, 1.0)
    return x, y


def train_multiclass_logreg(x: np.ndarray, y: np.ndarray, epochs: int = 600, lr: float = 0.08, l2: float = 1e-4) -> TrainingArtifacts:
    n_samples, n_features = x.shape
    n_classes = len(CLASS_NAMES)

    split = int(n_samples * 0.8)
    idx = np.random.permutation(n_samples)
    train_idx, test_idx = idx[:split], idx[split:]

    x_train, y_train = x[train_idx], y[train_idx]
    x_test, y_test = x[test_idx], y[test_idx]

    mean = x_train.mean(axis=0)
    std = x_train.std(axis=0) + 1e-6

    x_train_n = (x_train - mean) / std
    x_test_n = (x_test - mean) / std

    w = np.zeros((n_features, n_classes), dtype=np.float32)
    b = np.zeros((n_classes,), dtype=np.float32)

    y_onehot = np.eye(n_classes, dtype=np.float32)[y_train]

    for _ in range(epochs):
        logits = x_train_n @ w + b
        logits -= logits.max(axis=1, keepdims=True)
        exp_logits = np.exp(logits)
        probs = exp_logits / exp_logits.sum(axis=1, keepdims=True)

        grad_w = (x_train_n.T @ (probs - y_onehot)) / x_train_n.shape[0] + l2 * w
        grad_b = (probs - y_onehot).mean(axis=0)

        w -= lr * grad_w
        b -= lr * grad_b

    train_pred = np.argmax(x_train_n @ w + b, axis=1)
    test_pred = np.argmax(x_test_n @ w + b, axis=1)

    train_acc = float((train_pred == y_train).mean())
    test_acc = float((test_pred == y_test).mean())

    return TrainingArtifacts(
        weights=w,
        bias=b,
        mean=mean.astype(np.float32),
        std=std.astype(np.float32),
        train_accuracy=train_acc,
        test_accuracy=test_acc,
    )


def export_onnx(art: TrainingArtifacts, output_path: Path) -> None:
    input_info = helper.make_tensor_value_info("input", TensorProto.FLOAT, [None, len(FEATURE_NAMES)])
    output_label = helper.make_tensor_value_info("label", TensorProto.INT64, [None])
    output_probs = helper.make_tensor_value_info("probabilities", TensorProto.FLOAT, [None, len(CLASS_NAMES)])

    mean_init = helper.make_tensor("mean", TensorProto.FLOAT, [len(FEATURE_NAMES)], art.mean.tolist())
    std_init = helper.make_tensor("std", TensorProto.FLOAT, [len(FEATURE_NAMES)], art.std.tolist())
    w_init = helper.make_tensor("weights", TensorProto.FLOAT, list(art.weights.shape), art.weights.flatten().tolist())
    b_init = helper.make_tensor("bias", TensorProto.FLOAT, [len(CLASS_NAMES)], art.bias.tolist())

    nodes = [
        helper.make_node("Sub", ["input", "mean"], ["centered"]),
        helper.make_node("Div", ["centered", "std"], ["norm"]),
        helper.make_node("MatMul", ["norm", "weights"], ["mm"]),
        helper.make_node("Add", ["mm", "bias"], ["logits"]),
        helper.make_node("Softmax", ["logits"], ["probabilities"], axis=1),
        helper.make_node("ArgMax", ["probabilities"], ["label"], axis=1, keepdims=0),
    ]

    graph = helper.make_graph(
        nodes,
        "hid_stage2_classifier",
        [input_info],
        [output_label, output_probs],
        [mean_init, std_init, w_init, b_init],
    )

    model = helper.make_model(
        graph,
        producer_name="hidshield-trainer",
        producer_version="0.1.0",
        ir_version=10,
        opset_imports=[helper.make_operatorsetid("", 13)],
    )
    onnx.checker.check_model(model)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, output_path)


def sha256_hex(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 64)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    model_path = root / "models" / "hid_stage2_model.onnx"
    hash_path = root / "models" / "hid_stage2_model.sha256"
    meta_path = root / "models" / "hid_stage2_model.meta.json"

    x, y = generate_synthetic_dataset(samples_per_class=2500)
    art = train_multiclass_logreg(x, y)
    export_onnx(art, model_path)

    model_hash = sha256_hex(model_path)
    hash_path.write_text(model_hash + "\n", encoding="utf-8")

    metadata = {
        "model_name": "hid_stage2_model",
        "version": "0.1.0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "features": FEATURE_NAMES,
        "classes": CLASS_NAMES,
        "training": {
            "dataset": "synthetic_hid_behavior_v1",
            "samples": int(x.shape[0]),
            "train_accuracy": art.train_accuracy,
            "test_accuracy": art.test_accuracy,
            "algorithm": "multiclass_logistic_regression_gd",
        },
        "integrity": {
            "sha256": model_hash,
            "verification_mode": "sha256",
            "signature_status": "placeholder",
        },
    }
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Training complete")
    print(f"Model: {model_path}")
    print(f"SHA256: {model_hash}")
    print(f"Train accuracy: {art.train_accuracy:.4f}")
    print(f"Test accuracy: {art.test_accuracy:.4f}")


if __name__ == "__main__":
    main()
