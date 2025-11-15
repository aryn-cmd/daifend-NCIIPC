"""
core/discover.py

Simple discovery utilities used by the CLI to list source files for scanning.
"""
import os
from typing import List, Optional


def discover_files(repo_root: str, exts: Optional[List[str]] = None) -> List[str]:
	"""Recursively discover source files in repo_root.

	Skips common large or binary folders. Returns absolute file paths.
	"""
	if exts is None:
		exts = [
			".py", ".java", ".js", ".ts", ".c", ".cpp", ".cc", ".h", ".cs", ".php", ".go", ".rb"
		]
	out = []
	for root, dirs, files in os.walk(repo_root):
		# prune folders we don't want to descend into
		dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '__pycache__', 'build', 'dist')]
		for f in files:
			try:
				ext = os.path.splitext(f)[1].lower()
			except Exception:
				ext = ""
			if ext in exts:
				out.append(os.path.join(root, f))
	return out
