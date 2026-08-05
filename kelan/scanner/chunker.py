import os
from typing import Iterator, Dict, Any
from tree_sitter import Language, Parser
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts


class SemanticChunker:
    def __init__(self):
        # Initialize languages
        self.py_lang = Language(tspython.language(), "python")
        self.js_lang = Language(tsjs.language(), "javascript")
        self.ts_lang = Language(tsts.language_typescript(), "typescript")

        # Compile query strings
        self.py_query = self.py_lang.query(
            "(function_definition) @func (class_definition) @class"
        )
        self.js_query = self.js_lang.query(
            "(function_declaration) @func (class_declaration) @class (arrow_function) @arrow"
        )
        self.ts_query = self.ts_lang.query(
            "(function_declaration) @func (class_declaration) @class (arrow_function) @arrow"
        )

    def extract_chunks(self, file_path: str, code_bytes: bytes) -> Iterator[Dict[str, Any]]:
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".py":
            lang = self.py_lang
            query = self.py_query
        elif ext == ".js":
            lang = self.js_lang
            query = self.js_query
        elif ext in (".ts", ".tsx"):
            lang = self.ts_lang
            query = self.ts_query
        else:
            return

        parser = Parser()
        parser.set_language(lang)
        tree = parser.parse(code_bytes)

        captures = query.captures(tree.root_node)
        for node, capture_name in captures:
            yield {
                "file_path": file_path,
                "type": capture_name,
                "start_line": node.start_point[0],
                "end_line": node.end_point[0],
                "content": node.text.decode("utf-8", errors="replace"),
            }
