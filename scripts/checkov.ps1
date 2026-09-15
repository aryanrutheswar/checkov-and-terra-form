# PowerShell wrapper for Checkov execution
& python -c "import sys; from checkov.main import Checkov; sys.argv=['checkov'] + sys.argv[1:]; sys.exit(Checkov().run())" @args
exit $LASTEXITCODE
