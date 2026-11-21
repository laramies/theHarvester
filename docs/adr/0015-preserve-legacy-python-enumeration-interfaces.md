# Preserve legacy Python enumeration interfaces

Keep the original `theHarvester.__main__.sanitize_for_xml` import path as a re-export after moving XML serialization into the report module. Keep the retired result groups as empty entries in the legacy Python return tuple so existing positional callers retain their indexes. The dedicated DNS brute-force return path keeps its original result shape and persists completed evidence before it returns.

Credential configuration accepts case variants of known provider keys so existing files remain readable. When both spellings occur, the exact canonical spelling takes precedence so adding it gives the operator a deterministic override.
