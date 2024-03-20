import logging
import sys

from textual.logging import TextualHandler

from bogrod.tui.vexedit import VulnearabilityEditor

logging.basicConfig(
    level="NOTSET",
    handlers=[TextualHandler()],
)

from bogrod import main

if sys.argv[0] == '-c':
    args = '-s all -W releasenotes/sbom/jupyter-base-notebook.cdx.json'.split(' ')
    bogrod = main(args)
    app = bogrod.app
