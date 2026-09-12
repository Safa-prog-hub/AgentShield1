import os
import glob
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = "data/raw"
MODEL_PATH = "models/agentshield_rf.pkl"

# Number of rows read from each CSV.
# Keeps RAM usage reasonable on a laptop.
ROWS_PER_FILE = 50000

# Maximum samples used for each attack class.
SAMPLES_PER_CLASS = 5000

RANDOM_STATE = 42


# ============================================================
# LOAD DATA
# ============================================================

def load_dataset():

    files = glob.glob(
        os.path.join(DATA_PATH, "*.csv")
    )

    if not files:
        raise FileNotFoundError(
            "No CSV files found in data/raw"
        )

    print("\n======================================")
    print(" AgentShield CIC-IDS2017 ML Training")
    print("======================================")

    print(
        f"\nFound {len(files)} CSV files"
    )

    dataframes = []

    for file in files:

        filename = os.path.basename(file)

        print(
            f"\nLoading: {filename}"
        )

        df = pd.read_csv(
            file,
            nrows=ROWS_PER_FILE,
            low_memory=False
        )

        # Remove spaces from column names
        df.columns = (
            df.columns
            .str.strip()
        )

        print(
            f"Rows loaded: {len(df)}"
        )

        dataframes.append(df)

    data = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"\nCombined dataset shape: "
        f"{data.shape}"
    )

    return data


# ============================================================
# CLEAN DATA
# ============================================================

def clean_data(df):

    print("\nCleaning dataset...")

    # Remove spaces from column names
    df.columns = (
        df.columns
        .str.strip()
    )

    # Check Label
    if "Label" not in df.columns:

        raise ValueError(
            "ERROR: Label column was not found."
        )

    # Clean labels
    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    # Convert numeric columns where possible
    for column in df.columns:

        if column != "Label":

            df[column] = pd.to_numeric(
                df[column],
                errors="coerce"
            )

    # Replace infinity
    df = df.replace(
        [float("inf"), float("-inf")],
        pd.NA
    )

    # Remove missing values
    before = len(df)

    df = df.dropna()

    after = len(df)

    print(
        f"Removed {before - after} "
        "invalid rows"
    )

    # Remove duplicate rows
    before = len(df)

    df = df.drop_duplicates()

    after = len(df)

    print(
        f"Removed {before - after} "
        "duplicate rows"
    )

    print("\nClass distribution:")

    print(
        df["Label"].value_counts()
    )

    return df


# ============================================================
# BALANCE DATASET
# ============================================================

def balance_dataset(df):

    print("\n======================================")
    print(" Balancing Dataset")
    print("======================================")

    class_counts = (
        df["Label"]
        .value_counts()
    )

    balanced_parts = []

    for label, count in class_counts.items():

        class_data = df[
            df["Label"] == label
        ]

        sample_count = min(
            count,
            SAMPLES_PER_CLASS
        )

        print(
            f"{label}: "
            f"{count} available → "
            f"{sample_count} selected"
        )

        sampled = class_data.sample(
            n=sample_count,
            random_state=RANDOM_STATE
        )

        balanced_parts.append(
            sampled
        )

    balanced = pd.concat(
        balanced_parts,
        ignore_index=True
    )

    # Shuffle
    balanced = balanced.sample(
        frac=1,
        random_state=RANDOM_STATE
    ).reset_index(drop=True)

    print(
        f"\nBalanced dataset shape: "
        f"{balanced.shape}"
    )

    print("\nBalanced class distribution:")

    print(
        balanced["Label"].value_counts()
    )

    return balanced


# ============================================================
# REMOVE UNNECESSARY FEATURES
# ============================================================

def prepare_features(df):

    print("\nPreparing ML features...")

    X = df.drop(
        columns=["Label"]
    )

    y = df["Label"]

    # These fields are not useful for
    # general network attack detection.
    columns_to_remove = [
        "Flow ID",
        "Source IP",
        "Destination IP",
        "Timestamp"
    ]

    removed = []

    for column in columns_to_remove:

        if column in X.columns:

            X = X.drop(
                columns=[column]
            )

            removed.append(column)

    print(
        "\nRemoved columns:"
    )

    if removed:
        for column in removed:
            print(f" - {column}")
    else:
        print(" - None")

    # Make sure every feature is numeric
    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    # Replace invalid values
    X = X.replace(
        [float("inf"), float("-inf")],
        0
    )

    X = X.fillna(0)

    print(
        f"\nNumber of features: "
        f"{X.shape[1]}"
    )

    print(
        f"Number of samples: "
        f"{X.shape[0]}"
    )

    return X, y


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

def train_model(X_train, y_train):

    print("\n======================================")
    print(" Training Random Forest")
    print("======================================")

    print(
        "\nTraining samples:",
        len(X_train)
    )

    model = RandomForestClassifier(

        n_estimators=100,

        max_depth=20,

        min_samples_split=2,

        random_state=RANDOM_STATE,

        n_jobs=-1,

        class_weight="balanced"
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "\nRandom Forest training completed!"
    )

    return model


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print("\n======================================")
    print(" Model Evaluation")
    print("======================================")

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    print(
        f"\nAccuracy: "
        f"{accuracy:.4f}"
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    return accuracy


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model):

    os.makedirs(
        "models",
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        "\n======================================"
    )

    print(
        "Model saved successfully!"
    )

    print(
        f"Location: {MODEL_PATH}"
    )

    print(
        "======================================"
    )


# ============================================================
# MAIN TRAINING PIPELINE
# ============================================================

def train():

    # ----------------------------------------
    # 1. Load
    # ----------------------------------------

    df = load_dataset()

    # ----------------------------------------
    # 2. Clean
    # ----------------------------------------

    df = clean_data(df)

    # ----------------------------------------
    # 3. Balance
    # ----------------------------------------

    df = balance_dataset(df)

    # ----------------------------------------
    # 4. Prepare features
    # ----------------------------------------

    X, y = prepare_features(df)

    # ----------------------------------------
    # 5. Train/Test split
    # ----------------------------------------

    print(
        "\n======================================"
    )

    print(
        " Creating Train/Test Split"
    )

    print(
        "======================================"
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(

            X,
            y,

            test_size=0.20,

            random_state=RANDOM_STATE,

            stratify=y
        )
    )

    print(
        f"\nTraining samples: "
        f"{len(X_train)}"
    )

    print(
        f"Testing samples: "
        f"{len(X_test)}"
    )

    # ----------------------------------------
    # 6. Train
    # ----------------------------------------

    model = train_model(
        X_train,
        y_train
    )

    # ----------------------------------------
    # 7. Evaluate
    # ----------------------------------------

    evaluate_model(
        model,
        X_test,
        y_test
    )

    # ----------------------------------------
    # 8. Save
    # ----------------------------------------

    save_model(
        model
    )

    print(
        "\nAgentShield Member 1 "
        "ML training completed."
    )


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    train()




