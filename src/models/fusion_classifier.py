"""
fusion_classifier.py — PhishGuard Phase 6 (Quad-Modal Fusion)

The ultimate architecture. It learns per-sample weights across 4 modalities:
1. Text (Transformers)
2. Structural (MLP)
3. Visual (MobileNetV2 CNN)
4. Graph (GraphSAGE GNN)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import sys
import os

# Add paths for imports
sys.path.append(os.path.dirname(__file__))

from transformer_branch import TransformerBranch
from structural_branch import StructuralBranch
from visual_branch import VisualBranch
from graph_branch import GraphBranch

class AttentionFusion(nn.Module):
    """
    Treats the 4 embeddings as a sequence and applies multi-head self-attention.
    Outputs a fused embedding driven by dynamic scalar gating across 4 branches.
    """

    def __init__(self, embed_dim: int = 128, num_heads: int = 4):
        super().__init__()
        self.attention = nn.MultiheadAttention(embed_dim=embed_dim, num_heads=num_heads, batch_first=True)
        self.norm = nn.LayerNorm(embed_dim)
        
        # Maps the 4 attended tokens down to 4 dynamic scalar weights
        self.gate = nn.Sequential(
            nn.Linear(embed_dim * 4, 64),
            nn.ReLU(),
            nn.Linear(64, 4)
        )

    def forward(self, text_emb: torch.Tensor, struct_emb: torch.Tensor, vis_emb: torch.Tensor, graph_emb: torch.Tensor) -> torch.Tensor:
        # Stack the four embeddings as a length-4 sequence: (batch, 4, embed_dim)
        stacked = torch.stack([text_emb, struct_emb, vis_emb, graph_emb], dim=1)

        # Self-attention allows extreme cross-referencing
        attended, attn_weights = self.attention(stacked, stacked, stacked)
        attended = self.norm(attended + stacked) 

        # Generate dynamic gating weights
        flat_attended = attended.view(attended.size(0), -1)
        gate_logits = self.gate(flat_attended)  # (batch, 4)
        
        # Softmax ensures weights sum to 1.0
        gate_weights = F.softmax(gate_logits, dim=-1) # (batch, 4)

        # Extract attended modalities
        text_attended = attended[:, 0, :]
        struct_attended = attended[:, 1, :]
        vis_attended = attended[:, 2, :]
        graph_attended = attended[:, 3, :]

        # Quad-blend
        fused = (gate_weights[:, 0:1] * text_attended) + \
                (gate_weights[:, 1:2] * struct_attended) + \
                (gate_weights[:, 2:3] * vis_attended) + \
                (gate_weights[:, 3:4] * graph_attended)
                
        return fused, attn_weights, gate_weights


class PhishGuardModel(nn.Module):
    def __init__(self, embed_dim: int = 128, transformer_name: str = "distilbert-base-uncased", num_structural_features: int = 34):
        super().__init__()
        self.transformer_branch = TransformerBranch(model_name=transformer_name, output_dim=embed_dim)
        self.structural_branch = StructuralBranch(input_dim=num_structural_features, output_dim=embed_dim)
        self.visual_branch = VisualBranch(output_dim=embed_dim)
        self.graph_branch = GraphBranch(output_dim=embed_dim)
        
        self.fusion = AttentionFusion(embed_dim=embed_dim)

        self.classifier = nn.Sequential(
            nn.Linear(embed_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
        )

    def forward(self, input_ids, attention_mask, structural_features, images, graph_x, graph_edge_index, graph_batch_indices, return_attention: bool = False):
        text_emb = self.transformer_branch(input_ids, attention_mask)
        struct_emb = self.structural_branch(structural_features)
        vis_emb = self.visual_branch(images)
        graph_emb = self.graph_branch(graph_x, graph_edge_index, graph_batch_indices)

        fused, attn_weights, gate_weights = self.fusion(text_emb, struct_emb, vis_emb, graph_emb)
        logits = self.classifier(fused).squeeze(-1) 

        if return_attention:
            return logits, attn_weights, gate_weights
        return logits


if __name__ == "__main__":
    # Sanity check for Quad-Modal Fusion
    model = PhishGuardModel(embed_dim=128, num_structural_features=34)

    batch_size = 4
    num_nodes_in_graph = 100
    
    dummy_input_ids = torch.randint(0, 30522, (batch_size, 64))
    dummy_attention_mask = torch.ones((batch_size, 64), dtype=torch.long)
    dummy_structural = torch.randn(batch_size, 34)
    dummy_images = torch.randn(batch_size, 3, 224, 224)
    
    # Dummy Graph Data
    dummy_graph_x = torch.randn(num_nodes_in_graph, 64)
    dummy_edge_index = torch.randint(0, num_nodes_in_graph, (2, 200))
    dummy_batch_indices = torch.tensor([5, 10, 15, 20], dtype=torch.long) # IDs of the 4 URLs we are predicting

    logits, attn_weights, gate_weights = model(
        dummy_input_ids, dummy_attention_mask, dummy_structural, dummy_images, 
        dummy_graph_x, dummy_edge_index, dummy_batch_indices, 
        return_attention=True
    )
    
    print(f"Logits shape: {logits.shape}")
    assert logits.shape == (batch_size,)
    
    print(f"Gate weights shape: {gate_weights.shape}")
    assert gate_weights.shape == (batch_size, 4)
    
    print(f"Sample gate weights (Text, Struct, Vis, Graph): {gate_weights[0].detach().numpy()}")
    print("[ok] PhishGuardModel Quad-Modal sanity check passed.")
