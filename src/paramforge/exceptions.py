class ParamForgeError(Exception):
    """Base application error."""
class ScopeError(ParamForgeError): pass
class ConfigurationError(ParamForgeError): pass
