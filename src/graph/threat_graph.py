"""
threat_graph.py — PhishGuard Phase 6

Constructs the Threat Intelligence Graph.
Nodes: URLs, IP Addresses, ASNs, Registrars
Edges: Hosted_On (URL->IP), Registered_By (URL->Registrar), Routed_Through (IP->ASN)
"""

import pandas as pd
import json

class ThreatGraphBuilder:
    def __init__(self):
        self.node_mapping = {}
        self.edges = []
        self.node_features = []
        self.node_counter = 0
        
    def _get_or_create_node(self, entity_id, entity_type):
        if entity_id not in self.node_mapping:
            self.node_mapping[entity_id] = self.node_counter
            # Initialize with dummy features for demonstration
            # In production, use Node2Vec or FastText for initial embeddings
            self.node_features.append([1.0 if entity_type == 'url' else 0.0] * 64)
            self.node_counter += 1
        return self.node_mapping[entity_id]

    def add_relationship(self, url, ip_address, asn, registrar):
        """Adds edges for a single URL's infrastructure."""
        url_node = self._get_or_create_node(url, 'url')
        ip_node = self._get_or_create_node(ip_address, 'ip')
        asn_node = self._get_or_create_node(asn, 'asn')
        reg_node = self._get_or_create_node(registrar, 'registrar')
        
        # Add edges (undirected for message passing)
        self.edges.append((url_node, ip_node))
        self.edges.append((ip_node, url_node))
        
        self.edges.append((ip_node, asn_node))
        self.edges.append((asn_node, ip_node))
        
        self.edges.append((url_node, reg_node))
        self.edges.append((reg_node, url_node))

    def export_for_pyg(self):
        """Exports data formatted for PyTorch Geometric Data object."""
        import torch
        edge_index = torch.tensor(self.edges, dtype=torch.long).t().contiguous()
        x = torch.tensor(self.node_features, dtype=torch.float)
        return x, edge_index

if __name__ == "__main__":
    print("ThreatGraphBuilder initialized.")
