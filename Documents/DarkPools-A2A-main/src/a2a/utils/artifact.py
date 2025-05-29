import uuid

from a2a.types import Artifact, Part, TextPart


def new_text_artifact(
    name: str,
    text: str,
    description: str = '',
) -> Artifact:
    return Artifact(
        artifactId=str(uuid.uuid4()),
        parts=[Part(root=TextPart(text=text))],
        name=name,
        description=description,
    )
