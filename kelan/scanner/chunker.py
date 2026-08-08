import os
from collections.abc import Iterator
from typing import Any

import tree_sitter_javascript as tsjs
import tree_sitter_python as tspython
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser, Query, QueryCursor


class SemanticChunker:
    def __init__(self):

        self.py_lang = Language(tspython.language())
        self.js_lang = Language(tsjs.language())
        self.ts_lang = Language(tsts.language_typescript())


        self.py_query = Query(self.py_lang,
            "(function_definition) @func (class_definition) @class"
        )
        self.js_query = Query(self.js_lang,
            "(function_declaration) @func (class_declaration) @class (arrow_function) @arrow"
        )
        self.ts_query = Query(self.ts_lang,
            "(function_declaration) @func (class_declaration) @class (arrow_function) @arrow"
        )

    def extract_chunks(self, file_path: str, code_bytes: bytes) -> Iterator[dict[str, Any]]:
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

        parser = Parser(lang)
        tree = parser.parse(code_bytes)

        cursor = QueryCursor(query)
        captures = cursor.captures(tree.root_node)
        for capture_name, nodes in captures.items():
            for node in nodes:
                yield {
                    "file_path": file_path,
                    "type": capture_name,
                    "start_line": node.start_point[0],
                    "end_line": node.end_point[0],
                    "content": (node.text or b"").decode("utf-8", errors="replace"),
                }
