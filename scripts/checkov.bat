@echo off
rem Wrapper to run Checkov via Python on Windows environments
python -c "import sys; from checkov.main import Checkov; sys.argv=['checkov'] + sys.argv[1:]; sys.exit(Checkov().run())" %*
