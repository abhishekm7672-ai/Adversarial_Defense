from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

class MalwareDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100)

    def train(self, X_train, y_train):
        self.model.fit(X_train, y_train)

    def evaluate(self, X_test, y_test):
        predictions = self.model.predict(X_test)
        acc = accuracy_score(y_test, predictions)
        return acc

    def predict(self, X):
        return self.model.predict(X)