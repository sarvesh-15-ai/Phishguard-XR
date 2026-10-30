import React, { useEffect, useRef } from 'react';

const ThreatGraph = ({ graphData }) => {
  if (!graphData || !graphData.nodes) return null;

  // A very simple static layout engine for our specific graph structure
  // In a real app, you'd use D3.js or react-force-graph
  
  const width = 600;
  const height = 300;
  
  const getNodePosition = (index, total, group) => {
    // Target URL in center
    if (group === 1) return { x: width / 2, y: height / 2 };
    
    // Infrastructure nodes orbit the center
    const radius = 80;
    const angle = (index / (total - 1)) * Math.PI * 2;
    return {
      x: (width / 2) + radius * Math.cos(angle),
      y: (height / 2) + radius * Math.sin(angle)
    };
  };
  
  const positionedNodes = graphData.nodes.map((node, i) => {
    if (node.group === 1) {
       return { ...node, x: width/2, y: height/2 };
    }
    if (node.group === 2) return { ...node, x: width/2 - 120, y: height/2 - 60 }; // IP
    if (node.group === 3) return { ...node, x: width/2 - 220, y: height/2 - 100 }; // ASN
    if (node.group === 4) return { ...node, x: width/2 + 120, y: height/2 + 60 }; // Registrar
    
    // Malicious connected nodes
    if (node.group === 5 && i % 2 === 0) return { ...node, x: width/2 - 120, y: height/2 + 80 }; 
    if (node.group === 5) return { ...node, x: width/2 + 120, y: height/2 - 80 };
    
    return { ...node, x: Math.random() * width, y: Math.random() * height };
  });

  const getColor = (group) => {
    switch(group) {
      case 1: return '#38bdf8'; // Target (Blue)
      case 2: return '#94a3b8'; // IP (Gray)
      case 3: return '#64748b'; // ASN (Dark Gray)
      case 4: return '#cbd5e1'; // Registrar (Light Gray)
      case 5: return '#ef4444'; // Malicious (Red)
      default: return '#ffffff';
    }
  };

  return (
    <div style={{ width: '100%', overflowX: 'auto', background: 'rgba(15, 23, 42, 0.4)', borderRadius: '8px', border: '1px solid var(--glass-border)' }}>
      <svg width={width} height={height} style={{ display: 'block', margin: '0 auto' }}>
        {/* Draw Edges */}
        {graphData.links.map((link, i) => {
          const sourceNode = positionedNodes.find(n => n.id === link.source);
          const targetNode = positionedNodes.find(n => n.id === link.target);
          if (!sourceNode || !targetNode) return null;
          
          return (
            <g key={`edge-${i}`}>
              <line 
                x1={sourceNode.x} y1={sourceNode.y} 
                x2={targetNode.x} y2={targetNode.y} 
                stroke="rgba(255,255,255,0.2)" 
                strokeWidth="2" 
              />
              <text 
                x={(sourceNode.x + targetNode.x) / 2} 
                y={(sourceNode.y + targetNode.y) / 2 - 5}
                fill="rgba(255,255,255,0.5)"
                fontSize="10"
                textAnchor="middle"
              >
                {link.label}
              </text>
            </g>
          );
        })}
        
        {/* Draw Nodes */}
        {positionedNodes.map((node, i) => (
          <g key={`node-${i}`} transform={`translate(${node.x}, ${node.y})`}>
            <circle 
              r={node.group === 1 ? 16 : 12} 
              fill={getColor(node.group)} 
              stroke="rgba(255,255,255,0.2)"
              strokeWidth="2"
            />
            <text 
              y={node.group === 1 ? 28 : 22} 
              fill="var(--text-main)" 
              fontSize="12" 
              textAnchor="middle"
              fontWeight={node.group === 1 || node.group === 5 ? "bold" : "normal"}
            >
              {node.id}
            </text>
            <text 
              y={node.group === 1 ? 42 : 34} 
              fill="var(--text-muted)" 
              fontSize="10" 
              textAnchor="middle"
            >
              ({node.label})
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
};

export default ThreatGraph;
