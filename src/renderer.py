# Pretty print dictionary


def prettyPrintDict(d: dict, indent: int = 0):
    for key, value in d.items():
        if isinstance(value, dict):
            print("  " * indent + f"{key}:")
            prettyPrintDict(value, indent + 4)
        else:
            print("  " * indent + f"{key}: {value}")
