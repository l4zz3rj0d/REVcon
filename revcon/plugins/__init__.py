import os
import sys
import pkgutil
import importlib
from typing import List
from revcon.plugins.base import BasePlugin

def load_plugins() -> List[BasePlugin]:
    """Dynamically loads all modules in the plugins package and returns instances of BasePlugin subclasses."""
    plugins = []
    package_dir = os.path.dirname(__file__)
    
    # Temporarily append package directory to path to ensure relative imports work
    if package_dir not in sys.path:
        sys.path.insert(0, package_dir)

    for _, module_name, _ in pkgutil.iter_modules([package_dir]):
        # Skip base plugin module itself
        if module_name == "base":
            continue

        try:
            # Import the module
            module = importlib.import_module(f"revcon.plugins.{module_name}")
            
            # Find subclasses of BasePlugin defined in that module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, BasePlugin) and 
                    attr is not BasePlugin):
                    # Instantiate and register
                    plugins.append(attr())
        except Exception as e:
            # Gracefully fail loading a single plugin
            pass

    return plugins
