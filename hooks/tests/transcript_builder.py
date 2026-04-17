"""Builder for synthetic Claude Code transcript JSONL files.

Creates JSONL lines matching the format expected by _read_transcript_tail():
each line is {"role": "...", "message": {"content": [...]}} with content blocks
of type "text", "tool_use", or "tool_result".
"""

import json


class TranscriptBuilder:
    def __init__(self):
        self._lines = []

    def assistant_text(self, text):
        """Add an assistant message with a text content block."""
        self._lines.append(
            {
                "role": "assistant",
                "message": {"content": [{"type": "text", "text": text}]},
            }
        )
        return self

    def assistant_text_string(self, text):
        """Add an assistant message where content is a plain string (not a list)."""
        self._lines.append(
            {
                "role": "assistant",
                "message": {"content": text},
            }
        )
        return self

    def tool_use(self, tool_name, input_dict=None):
        """Add a tool_use content block (assistant calling a tool)."""
        self._lines.append(
            {
                "role": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "name": tool_name,
                            "input": input_dict or {},
                        }
                    ]
                },
            }
        )
        return self

    def tool_result(self, text):
        """Add a tool_result content block (tool response)."""
        self._lines.append(
            {
                "role": "tool",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "content": [{"type": "text", "text": text}],
                        }
                    ]
                },
            }
        )
        return self

    def build_lines(self):
        """Return list of dicts for conftest's run_hook(transcript_lines=...)."""
        return list(self._lines)

    def write_to(self, path):
        """Write JSONL to a file path. Returns the path for convenience."""
        with open(path, "w") as f:
            for line in self._lines:
                f.write(json.dumps(line) + "\n")
        return str(path)
