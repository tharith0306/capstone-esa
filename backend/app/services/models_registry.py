import threading

from app.core.config import Settings
from app.ml.features import FEATURES
from app.ml.models import ModelBundle


def bundle_problem(bundle: ModelBundle) -> str | None:
    """Why a saved bundle cannot be used by this code version (None if it is fine)."""
    if list(bundle.feature_names) != list(FEATURES):
        return "model bundle was trained with a different feature set"
    if getattr(bundle, "background", None) is None:
        return "model bundle predates LIME/DiCE support"
    return None


class ModelsNotTrained(RuntimeError):
    pass


class ModelRegistry:
    """Loads the trained bundle once and hands it out; reload() after retraining."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._bundle: ModelBundle | None = None
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self._bundle is not None or ModelBundle.exists(self.settings.model_dir)

    def get(self) -> ModelBundle:
        with self._lock:
            if self._bundle is None:
                if not ModelBundle.exists(self.settings.model_dir):
                    raise ModelsNotTrained("models are not trained yet: run `python -m app.cli train`")
                bundle = ModelBundle.load(self.settings.model_dir)
                problem = bundle_problem(bundle)
                if problem:
                    raise ModelsNotTrained(f"{problem}: run `python -m app.cli train`")
                self._bundle = bundle
            return self._bundle

    def reload(self) -> ModelBundle:
        with self._lock:
            self._bundle = None
        return self.get()
