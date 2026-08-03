"""Add analysis/ to sys.path so engine_types etc. can be imported directly."""
import os
import sys

_analysis_dir = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "analysis")
)
if _analysis_dir not in sys.path:
    sys.path.insert(0, _analysis_dir)
