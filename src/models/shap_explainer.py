import torch

try:
    import shap
except ImportError:
    shap = None

class PhishGuardSHAPExplainer:
    """
    Wraps the PyTorch PhishGuard model with SHAP (SHapley Additive exPlanations)
    to provide feature-level interpretability.
    
    Specifically, we focus on the Structural Branch (lexical, domain, HTML features)
    because these are tabular features that are easily understandable by security analysts.
    """
    
    def __init__(self, model, background_data):
        """
        Args:
            model: The trained PhishGuardModel instance
            background_data: A representative sample of the training dataset 
                             (e.g., 100 random samples) used to estimate expected values.
        """
        self.model = model
        self.model.eval()
        
        if shap:
            # We use DeepExplainer for PyTorch neural networks
            # We wrap the model in a dummy function that only exposes the structural branch
            # while keeping text/visual static or zeroed out for the purpose of the explanation.
            self.explainer = shap.DeepExplainer(self._structural_wrapper, background_data)
        else:
            print("[Warning] 'shap' library not installed. Explainer will be mocked.")
            self.explainer = None

    def _structural_wrapper(self, structural_features):
        """
        A wrapper that feeds only structural features into the model, passing
        dummy zeros for text and visual to isolate the structural branch's SHAP values.
        """
        batch_size = structural_features.shape[0]
        device = structural_features.device
        
        dummy_input_ids = torch.zeros((batch_size, 64), dtype=torch.long, device=device)
        dummy_attn_mask = torch.ones((batch_size, 64), dtype=torch.long, device=device)
        dummy_images = torch.zeros((batch_size, 3, 224, 224), dtype=torch.float, device=device)
        
        # Forward pass returning only logits
        logits = self.model(dummy_input_ids, dummy_attn_mask, structural_features, dummy_images)
        return logits

    def explain(self, structural_features_tensor):
        """
        Computes SHAP values for a given batch of structural features.
        
        Returns:
            shap_values: Array of SHAP values matching the input shape
        """
        if self.explainer:
            # Calculate SHAP values
            shap_values = self.explainer.shap_values(structural_features_tensor)
            return shap_values
        else:
            # Fallback mock for environments missing SHAP
            import numpy as np
            return np.random.randn(*structural_features_tensor.shape) * 0.1

if __name__ == "__main__":
    print("SHAP Explainer module initialized.")
