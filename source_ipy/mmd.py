import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, ConfusionMatrixDisplay
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

import numpy as np
from sklearn.datasets import make_classification

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def compute_gradients(y_true, y_pred):
    p = sigmoid(y_pred)
    grad = p - y_true
    hess = p * (1 - p)
    return grad, hess

def calc_leaf_value(g, h, lam, alpha):
    G = np.sum(g)
    H = np.sum(h)
    if G > alpha:
        return - (G - alpha) / (H + lam)
    elif G < -alpha:
        return - (G + alpha) / (H + lam)
    else:
        return 0.0

class TreeNode:
    def __init__(self, depth=0, max_depth=3):
        self.left = None
        self.right = None
        self.feature_index = None
        self.threshold = None
        self.value = None  # chỉ dùng khi là leaf
        self.depth = depth
        self.max_depth = max_depth

def build_tree(X, g, h, depth, max_depth, lam, gamma, alpha):
    node = TreeNode(depth=depth, max_depth=max_depth)

    if depth >= max_depth or X.shape[0] <= 1:
        node.value = calc_leaf_value(g, h, lam, alpha)
        return node

    best_gain = -np.inf
    best_split = None

    for feature_index in range(X.shape[1]):
        thresholds = np.unique(X[:, feature_index])
        for t in thresholds:
            left_idx = X[:, feature_index] <= t
            right_idx = ~left_idx

            if np.sum(left_idx) == 0 or np.sum(right_idx) == 0:
                continue

            GL, HL = np.sum(g[left_idx]), np.sum(h[left_idx])
            GR, HR = np.sum(g[right_idx]), np.sum(h[right_idx])

            gain = 0.5 * (GL**2 / (HL + lam) + GR**2 / (HR + lam) - (GL + GR)**2 / (HL + HR + lam)) - gamma

            if gain > best_gain:
                best_gain = gain
                best_split = (feature_index, t, left_idx, right_idx)

    if best_gain <= 0 or best_split is None:
        node.value = calc_leaf_value(g, h, lam, alpha)
        return node

    f_idx, t, left_idx, right_idx = best_split
    node.feature_index = f_idx
    node.threshold = t
    node.left = build_tree(X[left_idx], g[left_idx], h[left_idx], depth + 1, max_depth, lam, gamma, alpha)
    node.right = build_tree(X[right_idx], g[right_idx], h[right_idx], depth + 1, max_depth, lam, gamma, alpha)
    return node

def predict_tree(x, node):
    if node.value is not None:
        return node.value
    if x[node.feature_index] <= node.threshold:
        return predict_tree(x, node.left)
    else:
        return predict_tree(x, node.right)
    
class XGBoostClassifier:
    def __init__(self, n_estimators=10, max_depth=9, learning_rate=0.16730402817820244, lam=1.3289448722869181e-05, gamma=3.540362888980227, alpha=6.598711072054068): # Get From find_best_params
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.lr = learning_rate
        self.lam = lam
        self.gamma = gamma
        self.trees = []
        self.alpha = alpha

    def fit(self, X, y):
        y_pred = np.zeros_like(y, dtype=float)

        for _ in range(self.n_estimators):
            g, h = compute_gradients(y, y_pred)
            tree = build_tree(X, g, h, 0, self.max_depth, self.lam, self.gamma, self.alpha)
            self.trees.append(tree)

            update = np.array([predict_tree(x, tree) for x in X])
            y_pred += self.lr * update

    def predict(self, X):
        y_pred = np.zeros(X.shape[0])
        for tree in self.trees:
            y_pred += self.lr * np.array([predict_tree(x, tree) for x in X])
        return (sigmoid(y_pred) > 0.5).astype(int)

    def predict_proba(self, X):
        y_pred = np.zeros(X.shape[0])
        for tree in self.trees:
            y_pred += self.lr * np.array([predict_tree(x, tree) for x in X])
        prob = sigmoid(y_pred)
        return np.vstack([1 - prob, prob]).T

df = pd.read_csv("D:\Document\\University\CS114\CS114_ML_DLM\data\\alzheimer_done.csv")

X = df.drop(columns=["Diagnosis"])
y = df["Diagnosis"]


scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, stratify=y, random_state=42)

print(y_test.value_counts())


my_xgb = XGBoostClassifier(n_estimators=10, max_depth=9, learning_rate=0.16730402817820244, lam=1.3289448722869181e-05, gamma=3.540362888980227, alpha=6.598711072054068)
my_xgb.fit(X_train, y_train)
y_pred_my = my_xgb.predict(X_test)


lib_model = XGBClassifier(n_estimators=10, max_depth=9, learning_rate=0.16730402817820244, reg_lambda=1.3289448722869181e-05, gamma=3.540362888980227, reg_alpha=6.598711072054068)

lib_model.fit(X_train, y_train)
y_pred_lib = lib_model.predict(X_test)

fig, axs = plt.subplots(1, 2, figsize=(10, 4))

cm1 = confusion_matrix(y_test, y_pred_my)
disp1 = ConfusionMatrixDisplay(confusion_matrix=cm1, display_labels=["Healthy", "Diagnosis"])
disp1.plot(ax=axs[0], values_format=".0f")
print("Accuracy scratch:", accuracy_score(y_test, y_pred_my))

cm2 = confusion_matrix(y_test, y_pred_lib)
disp2 = ConfusionMatrixDisplay(confusion_matrix=cm2, display_labels=["Healthy", "Diagnosis"])
disp2.plot(ax=axs[1], values_format=".0f")
print("Accuracy library:", accuracy_score(y_test, y_pred_lib))

axs[0].set_title("Custom XGBoost")
axs[1].set_title("Library XGBoost")

plt.tight_layout()
plt.show()