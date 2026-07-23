import pefile
import numpy as np

def extract_behavior_features(file_path):
    """
    Extracts simulated behavioral features based on heuristics derived from the PE file.
    Returns: [api_entropy, process_spawn, registry_mod, network_activity]
    """
    try:
        pe = pefile.PE(file_path)
    except Exception:
        # Return neutral features if parsing fails
        return [0.5, 0.0, 0.0, 0.0]

    # 1. API call entropy
    # Calculated based on the number of unique DLLs and functions imported
    api_entropy = 0.0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
        func_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        # Normalize to a rough 0-1 scale
        api_entropy = min(1.0, (dll_count * 0.1) + (func_count * 0.01))

    # 2. Process spawn likelihood
    # Heuristic: Check for common process creation APIs
    spawn_keywords = [b"CreateProcess", b"ShellExecute", b"WinExec", b"OpenProcess"]
    process_spawn = 0.0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    for keyword in spawn_keywords:
                        if keyword in imp.name:
                            process_spawn = 1.0
                            break

    # 3. Registry modification likelihood
    # Heuristic: Check for registry manipulation APIs
    reg_keywords = [b"RegCreateKey", b"RegSetValue", b"RegDeleteKey", b"RegOpenKey"]
    registry_mod = 0.0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    for keyword in reg_keywords:
                        if keyword in imp.name:
                            registry_mod = 1.0
                            break

    # 4. Network activity likelihood
    # Heuristic: Check for networking APIs
    net_keywords = [b"InternetOpen", b"HttpOpen", b"WSAStartup", b"connect", b"send", b"recv"]
    network_activity = 0.0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    for keyword in net_keywords:
                        if keyword in imp.name:
                            network_activity = 1.0
                            break

    return [float(api_entropy), float(process_spawn), float(registry_mod), float(network_activity)]
