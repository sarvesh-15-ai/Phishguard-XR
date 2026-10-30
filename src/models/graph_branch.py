import torch
import torch.nn as nn
import torch.nn.functional as F

# Robust fallback in case torch_geometric fails to install due to C++ compilation issues
try:
    from torch_geometric.nn import SAGEConv
    PYG_AVAILABLE = True
except ImportError:
    PYG_AVAILABLE = False
    print("[Warning] torch_geometric not found. Using fallback linear layers for GraphSAGE.")

class GraphBranch(nn.Module):
    """
    Graph Neural Network (GNN) branch using GraphSAGE.
    Aggregates reputation features from a URL's neighboring nodes (IPs, ASNs)
    in the Threat Intelligence Graph.
    """

    def __init__(self, in_channels: int = 64, hidden_channels: int = 128, output_dim: int = 128):
        super().__init__()
        
        if PYG_AVAILABLE:
            # 2-layer GraphSAGE
            self.conv1 = SAGEConv(in_channels, hidden_channels)
            self.conv2 = SAGEConv(hidden_channels, output_dim)
        else:
            # Fallback MLP if PyG fails to install
            self.mlp = nn.Sequential(
                nn.Linear(in_channels, hidden_channels),
                nn.ReLU(),
                nn.Linear(hidden_channels, output_dim)
            )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor, batch_indices: torch.Tensor = None) -> torch.Tensor:
        """
        Args:
            x: Node feature matrix (num_nodes, in_channels)
            edge_index: Graph connectivity (2, num_edges)
            batch_indices: Indices of the specific URL nodes we are predicting for in this batch
            
        Returns:
            graph_emb: Tensor of shape (batch_size, output_dim)
        """
        if PYG_AVAILABLE:
            # Message passing across the graph
            x = self.conv1(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=0.3, training=self.training)
            x = self.conv2(x, edge_index)
        else:
            # Fallback
            x = self.mlp(x)
            
        # Extract only the embeddings for the target URLs in the current batch
        if batch_indices is not None:
            return x[batch_indices]
        
        # If no specific indices, return the whole batch (for testing)
        return x

if __name__ == "__main__":
    # Sanity check
    model = GraphBranch()
    dummy_x = torch.randn(10, 64)
    dummy_edge_index = torch.tensor([[0, 1, 1, 2], [1, 0, 2, 1]], dtype=torch.long)
    dummy_batch = torch.tensor([0, 2], dtype=torch.long)
    
    out = model(dummy_x, dummy_edge_index, dummy_batch)
    print(f"GraphBranch output shape: {out.shape}")
    assert out.shape == (2, 128)
    print("[ok] GraphBranch sanity check passed.")
