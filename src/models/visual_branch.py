import torch
import torch.nn as nn
import torchvision.models as models

class VisualBranch(nn.Module):
    """
    Extracts features from webpage screenshots to visually detect phishing attempts 
    (e.g., brand impersonation, fake login forms).
    """

    def __init__(self, output_dim: int = 128, pretrained: bool = True):
        super().__init__()
        
        # Load MobileNetV2 (lightweight CNN, good for local training/inference)
        weights = models.MobileNet_V2_Weights.DEFAULT if pretrained else None
        self.backbone = models.mobilenet_v2(weights=weights)
        
        # MobileNetV2's final classifier is a Sequential block. We want to replace it.
        # The feature map before the classifier is 1280-dimensional.
        in_features = self.backbone.classifier[1].in_features
        
        # Replace the original 1000-class ImageNet head with our embedding projection
        self.backbone.classifier = nn.Sequential(
            nn.Dropout(p=0.2, inplace=False),
            nn.Linear(in_features, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, output_dim)
        )

    def forward(self, images: torch.Tensor) -> torch.Tensor:
        """
        Args:
            images: Tensor of shape (batch_size, 3, 224, 224)
        Returns:
            visual_emb: Tensor of shape (batch_size, output_dim)
        """
        return self.backbone(images)

if __name__ == "__main__":
    # Sanity check
    model = VisualBranch(output_dim=128)
    dummy_images = torch.randn(4, 3, 224, 224)
    out = model(dummy_images)
    print(f"VisualBranch output shape: {out.shape}")
    assert out.shape == (4, 128)
    print("[ok] VisualBranch sanity check passed.")
