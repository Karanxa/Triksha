import ast
import logging
from typing import List
from ..result import Indicator
from .base import BaseScanner

logger = logging.getLogger("repo_scanner")


class ASTScanner(BaseScanner):
    def scan(self, file_path: str, content: str) -> List[Indicator]:
        indicators = []
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content)
                analyzer = PythonAnalyzer()
                analyzer.visit(tree)

                for imp in analyzer.imports:
                    indicators.append(Indicator(type="ast_import", value=imp, file=file_path))

                for cls in analyzer.classes:
                    indicators.append(Indicator(type="ast_class", value=cls, file=file_path))

            except SyntaxError:
                logger.debug("Syntax error parsing %s", file_path)
            except Exception as e:
                logger.warning("AST parse error %s: %s", file_path, e)

        return indicators


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.imports = []
        self.classes = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.append(node.module)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        self.generic_visit(node)
