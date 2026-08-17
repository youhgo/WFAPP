import pkgutil
import importlib

# Load all modules in this package to trigger @register_elk_processor decorators
for _, module_name, _ in pkgutil.iter_modules(__path__):
    importlib.import_module(f".{module_name}", package=__name__)
