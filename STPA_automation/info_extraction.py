# flake8: noqa: E501
import xml.etree.ElementTree as ET
from pathlib import Path
from utils import DAnalysis, DView, DRepresentationDescriptor, DSemanticDiagram, DNode, DEdge

PROJECT_DIR = Path("GCAP_NTP241_UNINA")
REQUIRED_PLUGINS = {"com.thalesgroup.mde.capella.stpa", "org.polarsys.capella.cybersecurity"}


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

if __name__ == "__main__":

    afm_tree, aird_tree = load_project(PROJECT_DIR)
    check_required_plugins(afm_tree.getroot())
    root = aird_tree.getroot()

    danalysis = parse_danalysis(root[0])
    HCS_id = find_diagram(danalysis, "[HCS] Hierarchical Control Structure Diagram")
    
    hcs_dsemantic = return_dsemantic(root, HCS_id)
    nodes, edges = extract_STPA(hcs_dsemantic)
       
