from importlib import import_module
from surgeon import SURGEONTarget
from halucinator.bp_handlers import *
from halucinator.peripheral_models import *
import halucinator.constants as constants
import logging
import sys

imported_modules = sys.modules
initialized_classes = dict()
handler_lookup = dict()
# Create a target upon initialization, reuse it across invocations
target = SURGEONTarget()

# Set log level
logging.basicConfig(level=logging.INFO)


def call_handler(handler: str, addr: int) -> bool:
    """Call a certain handler and initialize its corresponding class if necessary.

    Args:
        handler (str): the handler to be called
        addr (int): the address of the intercepted HAL function

    Returns:
        bool: True on success, False on error
    """
    # Explicitly state global variables that we reuse/modify
    global imported_modules
    global initialized_classes
    global handler_lookup
    global target

    # Initialize and resolve the handler object/function if not done yet
    if handler not in handler_lookup.keys():
        # Split passed string up into module, class, function
        split_str = handler.split(".")
        assert len(split_str) >= 2
        module_str = ".".join(split_str[:-2])
        class_str = split_str[-2]
        function_str = split_str[-1]

        # Get the corresponding module => only import once
        if module_str not in imported_modules:
            imported_modules[module_str] = import_module(module_str)
        module = imported_modules[module_str]

        # Get the corresponding object => only create one object
        handler_class = getattr(module, class_str)
        if handler_class not in initialized_classes:
            initialized_classes[handler_class] = handler_class()
        handler_object = initialized_classes[handler_class]

        # Get the corresponding function
        handler_func = getattr(handler_object, function_str)
        handler_lookup[handler] = handler_func

    # Actually call the handler function
    handler_lookup[handler](target, addr)

    return True
