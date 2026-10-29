from plugins.anonymous import runner as anonymous_runner

MODULES = {
    "anonymous": anonymous_runner,
}


def get_module(name: str):
    return MODULES.get(name.lower())


def list_modules():
    return sorted(MODULES.keys())
