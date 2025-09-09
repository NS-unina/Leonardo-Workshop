# flake8: noqa: E501
import re
from typing import List
import xml.etree.ElementTree as ET
from pathlib import Path
from utils import DAnalysis, DView, DRepresentationDescriptor, DSemanticDiagram, DNode, DEdge
import psycopg2
PROJECT_DIR = Path("GCAP_NTP241_UNINA")
REQUIRED_PLUGINS = {"com.thalesgroup.mde.capella.stpa", "org.polarsys.capella.cybersecurity"}


def get_db_conn():

    return psycopg2.connect(
        dbname="mydb",
        user="myuser",
        password="mypassword",
        host="localhost",
        port="5432"
    )


def load_project(project_dir: Path) -> tuple[ET.ElementTree, ET.ElementTree]:
    """Load Capella project files.

    Args:
        project_dir (Path): Path to the project directory.

    Returns:
        tuple[ET.ElementTree, ET.ElementTree]: Parsed AFM and AIRD XML trees.
    """
    
    AIRD_NAME = project_dir / f"{project_dir.name}.aird"
    AFM_NAME = project_dir / f"{project_dir.name}.afm"

    afm_tree = ET.parse(AFM_NAME)
    aird_tree = ET.parse(AIRD_NAME)

    return afm_tree, aird_tree


def check_required_plugins(root: ET.Element):
    """Check that all required Capella plugins are present.

    Args:
        root (ET.Element): Root of the parsed `.afm` XML tree.

    Raises:
        RuntimeError: If any required plugin is missing.
    """
    found = {
        el.get("vpId")
        for el in root.iter()
        if el.tag.split('}')[-1] == "viewpointReferences" and el.get("vpId")
    }

    missing = REQUIRED_PLUGINS - found

    if missing:
        raise RuntimeError(f"Missing required plugin(s): {', '.join(missing)}")


def parse_danalysis(root: ET.Element) -> DAnalysis:
    """Parse a DAnalysis XML element into a DAnalysis object.

    Args:
        root (ET.Element): Root DAnalysis XML element.

    Returns:
        DAnalysis: Parsed analysis with views and descriptors.
    """
    
    analysis = DAnalysis(uid=root.attrib.get("uid"))

    # semantic resources
    for sr in root.findall(".//semanticResources"):
        if sr.text:
            analysis.semantic_resources.append(sr.text)

    # views
    for v in root.findall(".//{*}ownedViews"):
        dview = DView(uid=v.attrib.get("uid"), viewpoint=None)

        # find viewpoint child
        vp = v.find(".//{*}viewpoint")
        if vp is not None:
            dview.viewpoint = vp.attrib.get("href")

        # find descriptors child
        for d in v.findall(".//{*}ownedRepresentationDescriptors"):
            desc = DRepresentationDescriptor(
                uid=d.attrib.get("uid"), 
                name=d.attrib.get("name", ""),
                ref_path=d.attrib.get("repPath", "") 
            )
            dview.descriptors.append(desc)

        analysis.views.append(dview)

    return analysis


def find_diagram(analysis: DAnalysis, diagram: str) -> str | None:
    """Find the reference path of a diagram by name.

    Args:
        analysis (DAnalysis): Parsed Capella analysis.
        diagram (str): Name of the diagram to search for.

    Returns:
        str | None: The diagram reference path if found, otherwise None.
    """
    for v in analysis.views:
        # print(f"  viewpoint = {v.viewpoint}")
        for d in v.descriptors:
            if d.name == diagram:
                return d.ref_path


def return_dsemantic(root: ET.Element, id: str) -> ET.Element | None:
    
    def parse_dsemantic_diagram(elem: ET.Element) -> DSemanticDiagram:
        diagram = DSemanticDiagram(uid=elem.attrib.get("uid"))

        return diagram

    
    """Return the DSemanticDiagram element matching the given HCS id.

    Args:
        root (ET.Element): Root XML element of the AIRD file.
        hcs_id (str): Identifier of the HCS diagram (with or without leading '#').

    Returns:
        ET.Element | None: The matching DSemanticDiagram element, or None if not found.
    """
    target_id = id.lstrip("#")

    for child in root:
        if "DSemanticDiagram" in child.tag:
            dsemantic = parse_dsemantic_diagram(child)
            if dsemantic.uid == target_id:
                print(dsemantic.uid)
                return child
    return None


def extract_STPA(hcs_dsemantic: ET.Element) -> tuple[list[DNode], list[DEdge]]:

    """Extract STPA nodes and edges from a DSemanticDiagram.

    Args:
        hcs_dsemantic (ET.Element): XML element of the HCS DSemanticDiagram.

    Returns:
        tuple[list[DNode], list[DEdge]]: Lists of extracted nodes and edges.
    """

    def _xmi_type(el: ET.Element) -> str | None:
        for k, v in el.attrib.items():
            if k.endswith("type"):
                return v
        return None

    nodes = []
    edges = []

    for ode in hcs_dsemantic.findall(".//{*}ownedDiagramElements"):

        typ = _xmi_type(ode)
        if typ == "diagram:DNodeContainer":
            node = DNode(
                uid = ode.attrib.get("uid", ""),
                name = (ode.attrib.get("name") or ""),
                outgoingEdges = ode.attrib.get("outgoingEdges", "")
            )
            
            nodes.append(node)
            # print(node.name)

        elif typ == "diagram:DEdge":
            edge = DEdge(
                uid=ode.attrib.get("uid", ""),
                name=(ode.attrib.get("name") or "").strip() or None,
                source_uid=ode.attrib.get("sourceNode"),
                target_uid=ode.attrib.get("targetNode"),
            )

            edges.append(edge)
            # print(edge.name)

    return nodes, edges



def resolve_edge_names(nodes: List[DNode], edges: List[DEdge]) -> None:
    """Resolve and assign names for edges based on node mappings.

    Args:
        nodes (list[DNode]): List of node objects.
        edges (list[DEdge]): List of edge objects (modified in place).
    """
    uid_to_name = {n.uid: n.name for n in nodes}

    for e in edges:

        if e.source_uid in uid_to_name:
            e.source_name = uid_to_name[e.source_uid]
        if e.target_uid in uid_to_name:
            e.target_name = uid_to_name[e.target_uid]


def edges_to_controlflow_facts(edges) -> list[str]:
    """Convert edges into controlFlow facts for analysis.

    Args:
        edges (list[DEdge]): List of edges with resolved names or UIDs.

    Returns:
        list[str]: Generated controlFlow facts as strings.
    """
    
    facts: list[str] = []
    for e in edges:

        src = _to_atom(getattr(e, "source_name", None) or e.source_uid, "unknown_src")
        tgt = _to_atom(getattr(e, "target_name", None) or e.target_uid, "unknown_tgt")
        lbl = _to_atom(e.name or e.uid, "edge")
        facts.append(f"controlFlow({src}, {tgt}, {lbl}).")
    
    return facts


def extract_protocols(edges: List[DEdge]) -> list[str]:
    """Extract bracketed protocol names from edge names.

    Args:
        edges (list[DEdge]): List of edge objects. 

    Returns:
        list[str]: All extracted protocol names.
    """
    protocols: list[str] = []

    for e in edges:
        if not e.name:
            continue

        match = re.search(r"\[(.*?)\]", e.name)
        if match:
            e.bracket_name = match.group(1)
            protocols.append(e.bracket_name)

    return protocols


def _to_atom(s: str | None, fallback: str = "unknown") -> str:
    """Normalize a string into a safe atom identifier.

    - Converts to lowercase.
    - Replaces non-word characters with underscores.
    - Collapses multiple underscores and trims them.
    - Ensures the result starts with a letter (prefixes 'x_' if needed).
    - Falls back to a default string if input is None or empty.

    Args:
        s (str | None): Input string to normalize.
        fallback (str): Value to use if input is invalid or empty.

    Returns:
        str: Normalized atom string.
    """
    
    if not s:
        s = fallback
    s = s.lower()
    s = re.sub(r"[^\w]+", "_", s)        # non-word -> _
    s = re.sub(r"_+", "_", s).strip("_") # collapse/trim _
    if not s:
        s = fallback
    if not re.match(r"^[a-z]", s):
        s = "x_" + s
    return s


def db_to_facts(bracket_names: list[str]) -> list[str]:
    """Extract facts (physicalLayer, weaknessPhysicalLayer, attackGoal) from the database.

    Args:
        bracket_names (list[str]): Protocol identifiers to filter.

    Returns:
        list[str]: Generated fact strings.
    """
    facts: list[str] = []

    if not bracket_names:
        return facts

    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            placeholders = ",".join(["%s"] * len(bracket_names))

            # physicalLayer facts
            cur.execute(f"""
                SELECT p.protocol, pl.dest, pl.source, p.layer
                FROM physical_layer pl
                JOIN protocols p ON pl.protocol = p.protocol
                WHERE p.protocol IN ({placeholders})
                ORDER BY p.protocol, pl.dest, pl.source;
            """, bracket_names)
            for protocol, dest, source, layer in cur.fetchall():
                facts.append(
                    f"physicalLayer({_to_atom(protocol)}, {_to_atom(dest)}, {_to_atom(source)}, {_to_atom(layer)})."
                )

            # weaknessPhysicalLayer facts
            cur.execute(f"""
                SELECT vulnerability, protocol, zone
                FROM weakness_physical_layer
                WHERE protocol IN ({placeholders})
                ORDER BY vulnerability;
            """, bracket_names)
            for vuln, protocol, zone in cur.fetchall():
                facts.append(
                    f"weaknessPhysicalLayer({_to_atom(vuln)}, {_to_atom(protocol)}, {_to_atom(zone)})."
                )

            # attackGoal facts
            cur.execute("""
                SELECT goal_type, target
                FROM attack_goals
                ORDER BY id;
            """)
            for goal_type, target in cur.fetchall():
                facts.append(
                    f"attackGoal({_to_atom(goal_type)}({_to_atom(target)}))."
                )

    except Exception as e:
        print(f"[WARN] Skipping DB extraction: {e}")

    return facts


if __name__ == "__main__":

    afm_tree, aird_tree = load_project(PROJECT_DIR)
    check_required_plugins(afm_tree.getroot())
    root = aird_tree.getroot()

    danalysis = parse_danalysis(root[0])
    HCS_id = find_diagram(danalysis, "[HCS] Hierarchical Control Structure Diagram")
    
    hcs_dsemantic = return_dsemantic(root, HCS_id)
    nodes, edges = extract_STPA(hcs_dsemantic)
       
    resolve_edge_names(nodes, edges)
    facts = edges_to_controlflow_facts(edges)

    protocols = extract_protocols(edges)
    print(protocols)

    facts += db_to_facts(protocols)

    out_file = Path("interactions.pl")
    out_file.write_text("\n".join(facts) + "\n", encoding="utf-8")

