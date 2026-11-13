from src.ml_predictor import URLModelPredictor
from src.url_features import extract_url_features


def test_saved_model_loads_and_predicts_probability():
    predictor = URLModelPredictor()
    assert predictor.available, predictor.load_error
    features = extract_url_features("https://www.python.org/")
    prediction = predictor.predict(features["normalized_url"], features["numeric"])
    assert prediction.error is None
    assert prediction.probability is not None
    assert 0.0 <= prediction.probability <= 1.0
