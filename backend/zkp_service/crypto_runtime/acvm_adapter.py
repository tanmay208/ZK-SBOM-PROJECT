import json
import logging
import os
import shutil
import subprocess

logger = logging.getLogger("zkp_service.acvm_adapter")

RUNTIME_DIR = os.path.dirname(os.path.abspath(__file__))
EXECUTE_SCRIPT = os.path.join(RUNTIME_DIR, "execute_acvm.mjs")


def resolve_node_command() -> tuple[list[str], bool] | tuple[None, bool]:
    """
    Resolve a functional Node.js invocation command across POSIX and Windows/WSL environments.
    Returns (cmd_list, is_windows_node).
    """
    # 1. Check direct 'node' on PATH
    node_bin = shutil.which("node")
    if node_bin:
        is_win = node_bin.lower().endswith(".exe") or "/mnt/c/" in node_bin or "C:\\" in node_bin
        return [node_bin], is_win

    # 2. Check local user binaries in POSIX (~/.bin/node or ~/.local/bin/node)
    user_home = os.path.expanduser("~")
    for candidate in [
        os.path.join(user_home, ".bin", "node"),
        os.path.join(user_home, ".local", "bin", "node"),
        "/usr/local/bin/node",
        "/usr/bin/node",
        "/mnt/c/Program Files/nodejs/node.exe",
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            is_win = candidate.lower().endswith(".exe") or "/mnt/c/" in candidate or candidate == os.path.join(user_home, ".bin", "node")
            return [candidate], is_win

    # 3. If on Windows native host
    if os.name == "nt":
        win_candidates = [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe",
        ]
        for candidate in win_candidates:
            if os.path.isfile(candidate):
                return [candidate], True

    return None, False


def to_node_path(path: str, is_win_node: bool) -> str:
    """Convert POSIX WSL path to Windows path format if Node binary is a Windows executable."""
    if is_win_node and shutil.which("wslpath"):
        try:
            res = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, check=True)
            return res.stdout.strip()
        except Exception:
            pass
    return path


def solve_witness_acvm(
    circuit_json_path: str,
    inputs_dict: dict,
    output_witness_path: str,
    timeout: int | float = 120,
) -> bool:
    """
    Execute precompiled ACIR bytecode directly via the pinned Noir JS ACVM runtime.

    Bypasses Nargo CLI source compilation while guaranteeing identical witness outputs
    accepted by Barretenberg 0.46.1.

    Args:
        circuit_json_path: Path to precompiled circuit JSON artifact (containing bytecode & ABI)
        inputs_dict: Clean Python dictionary of inputs conforming to circuit ABI
        output_witness_path: Target path for the solved, gzip-compressed witness output
        timeout: Maximum duration allowed for ACVM execution in seconds

    Returns:
        True if witness was solved and validated successfully, False otherwise.
    """
    if not os.path.isfile(circuit_json_path):
        logger.error("ACVM error: Circuit JSON artifact not found at: %s", circuit_json_path)
        return False

    node_cmd, is_win_node = resolve_node_command()
    if not node_cmd:
        logger.warning("Node.js runtime not found; ACVM execution unavailable.")
        return False

    tmp_dir = os.path.dirname(output_witness_path)
    inputs_path = os.path.join(tmp_dir, f"inputs_{os.getpid()}_{id(inputs_dict)}.json")

    try:
        with open(inputs_path, "w", encoding="utf-8") as f:
            json.dump(inputs_dict, f, indent=2)

        script_arg = to_node_path(EXECUTE_SCRIPT, is_win_node)
        circuit_arg = to_node_path(circuit_json_path, is_win_node)
        inputs_arg = to_node_path(inputs_path, is_win_node)
        output_arg = to_node_path(output_witness_path, is_win_node)

        cmd = node_cmd + [script_arg, circuit_arg, inputs_arg, output_arg]

        res = subprocess.run(
            cmd,
            cwd=RUNTIME_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if res.returncode != 0:
            logger.error("ACVM witness solving failed (code=%d): %s", res.returncode, res.stderr.strip())
            return False

        # Fail-closed witness verification
        if not os.path.isfile(output_witness_path) or os.path.getsize(output_witness_path) < 100:
            logger.error("ACVM witness output missing or unexpectedly small: %s", output_witness_path)
            return False

        with open(output_witness_path, "rb") as wf:
            header = wf.read(2)
            if header != b"\x1f\x8b":
                logger.error("ACVM witness output is not valid GZIP (magic bytes: %s)", header.hex())
                return False

        logger.info(
            "ACVM witness solved successfully: %s (%d bytes)",
            os.path.basename(output_witness_path),
            os.path.getsize(output_witness_path),
        )
        return True

    except subprocess.TimeoutExpired as exc:
        logger.error("ACVM witness solving timed out after %ss: %s", exc.timeout, exc)
        return False
    except Exception as exc:
        logger.error("Unexpected error in ACVM witness solving: %s", exc)
        return False
    finally:
        if os.path.isfile(inputs_path):
            try:
                os.remove(inputs_path)
            except OSError:
                pass
