"""
structural_branch.py — PhishGuard Phase 3b

Encodes the structural/lexical features (from Phase 2's
lexical_features.csv) into a fixed-size embedding, to be fused with the
transformer branch's text embedding.

NOTE ON SCOPE: the build guide's "full" design calls for a Graph Neural
Network over the page's DOM/hyperlink graph. That requires scraping live
HTML for every URL, which is slow, and risky to do at scale for URLs
that are still-active phishing pages. This branch uses the simplified,
scoped-down version explicitly suggested in the build guide: a small
MLP (multi-layer perceptron) over the 12 handcrafted structural/lexical
features you already extracted in Phase 2 (url_length, num_dots,
has_ip_host, suspicious_tld, domain_entropy, etc).

This is a legitimate, defensible design choice for a final-year project
— just document it clearly in your paper as a scoped simplification of
the full GNN design, with full DOM-graph GNN listed as future work.
If you have time later, this class can be swapped for a real
torch_geometric GCN/GAT without changing anything else in the pipeline
(the fusion layer only cares about the output embedding size).
"""

import torch
import torch.nn as nn

NUM_LEXICAL_FEATURES = 12  # matches the columns produced by extract_features.py


class StructuralBranch(nn.Module):
    """
    A simple Multi-Layer Perceptron (MLP) to process the handcrafted
    structural features (lexical, domain, HTML).
    """

    def __init__(self, input_dim: int = 34, output_dim: int = 128):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.2),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, output_dim),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        # features: (batch, NUM_LEXICAL_FEATURES) — already numeric, should
        # be normalized/standardized before this (see train.py in Phase 4)
        return self.mlp(features)  # (batch, output_dim)


if __name__ == "__main__":
    model = StructuralBranch(output_dim=128)
    dummy_features = torch.randn(4, NUM_LEXICAL_FEATURES)  # batch of 4

    output = model(dummy_features)
    print(f"Output shape: {output.shape}")  # expect torch.Size([4, 128])
    assert output.shape == (4, 128), "Unexpected output shape!"
    print("[ok] StructuralBranch sanity check passed.")
