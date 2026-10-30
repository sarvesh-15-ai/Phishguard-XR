"""
transformer_branch.py — PhishGuard Phase 3a

Wraps a pretrained DistilBERT as the text/URL encoder. Takes tokenized
input (from Phase 2's tokenized.pt) and outputs a fixed-size embedding
per URL, which will later be combined with the structural branch.

This branch is intentionally kept simple: we reuse a pretrained
transformer's [CLS] representation rather than training one from
scratch — training a transformer from zero needs far more data and
compute than a final-year project has time for. Fine-tuning a
pretrained one is the standard, defensible approach (same choice
URLTran and PhishTransformer made in the papers you cited).
"""

import torch
import torch.nn as nn
from transformers import AutoModel


class TransformerBranch(nn.Module):
    def __init__(self, model_name: str = "distilbert-base-uncased", output_dim: int = 128, freeze_base: bool = False):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)
        hidden_size = self.encoder.config.hidden_size  # 768 for distilbert-base

        if freeze_base:
            # Optional: freeze the pretrained weights and only train the
            # projection head. Faster, needs less data, but usually a bit
            # less accurate than full fine-tuning. Good fallback if training
            # time is tight.
            for param in self.encoder.parameters():
                param.requires_grad = False

        self.projection = nn.Sequential(
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, output_dim),
        )

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # Use the [CLS] token's representation (first token) as the
        # sentence-level embedding — standard practice for BERT-family models.
        cls_embedding = outputs.last_hidden_state[:, 0, :]  # (batch, hidden_size)
        return self.projection(cls_embedding)  # (batch, output_dim)


if __name__ == "__main__":
    # Quick sanity check — run this file directly to confirm shapes work
    # before wiring it into the full model.
    model = TransformerBranch(output_dim=128)
    dummy_input_ids = torch.randint(0, 30522, (4, 64))       # batch of 4, seq_len 64
    dummy_attention_mask = torch.ones((4, 64), dtype=torch.long)

    output = model(dummy_input_ids, dummy_attention_mask)
    print(f"Output shape: {output.shape}")  # expect torch.Size([4, 128])
    assert output.shape == (4, 128), "Unexpected output shape!"
    print("[ok] TransformerBranch sanity check passed.")
