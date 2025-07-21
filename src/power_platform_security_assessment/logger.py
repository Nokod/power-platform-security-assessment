from colorama import Fore


class Logger:
    def __init__(self, debug_enabled=False):
        self._debug_enabled = debug_enabled

    def log(self, message="", log_level="info"):
        if message == "":
            print()

        # If debug is disabled, only print info level messages
        if not self._debug_enabled and log_level != "info":
            return

        color = {
            "debug": Fore.RESET,
            "info": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
        }.get(log_level, Fore.RESET)

        prefix = f"[{log_level.upper()}]" if log_level != "info" else ""
        print(f"{color}{prefix} {message}{Fore.RESET}")
