import sys
from server import main  # noqa: F401  (app/ is on sys.path via server.py's HERE insert when run as a module)

if __name__ == "__main__":
    if "--open" not in sys.argv:
        sys.argv.append("--open")
    main()
