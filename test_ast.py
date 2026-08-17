import ast

code = """
class MyClass:
    pass
register_preprocessor('test')(MyClass)
"""

tree = ast.parse(code)
for node in tree.body:
    if isinstance(node, ast.ClassDef):
        print(f"Decorators: {node.decorator_list}")
