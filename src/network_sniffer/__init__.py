__version__ = "0.1.0"

from network_sniffer.app import NetworkSnifferApp


def main() -> None:
    NetworkSnifferApp().run()
