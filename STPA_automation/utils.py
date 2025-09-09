from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DNode:
    uid: str
    name: Optional[str] = None
    outgoingEdges: Optional[str] = None  # need to split


@dataclass
class DEdge:
    uid: str
    name: Optional[str] = None
    source_uid: Optional[str] = None
    target_uid: Optional[str] = None
    source_name: Optional[str] = None
    target_name: Optional[str] = None


@dataclass
class DRepresentation:
    uid: str
    name: Optional[str] = None
    rep_type: Optional[str] = None  # diagram:DDiagram, diagram:DTable, etc.
    nodes: List[DNode] = field(default_factory=list)
    edges: List[DEdge] = field(default_factory=list)


@dataclass
class DRepresentationDescriptor:
    uid: str
    name: str
    ref_path: Optional[str] = None  # diagram:DDiagram, diagram:DTable, etc.
    representation: Optional[DRepresentation] = None


@dataclass
class DView:
    uid: str
    viewpoint: Optional[str] = None
    descriptors: List[DRepresentationDescriptor] = field(default_factory=list)


@dataclass
class DAnalysis:
    uid: str
    semantic_resources: List[str] = field(default_factory=list)
    views: List[DView] = field(default_factory=list)


@dataclass
class DSemanticDiagram:
    uid: str
    nodes: List[DNode] = field(default_factory=list)
    edges: List[DEdge] = field(default_factory=list)
