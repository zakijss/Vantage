# Contributing to Vantage

Bug reports, ideas and pull requests are welcome. Use the issue forms for
the first two; for security problems, see [SECURITY.md](SECURITY.md).

Vantage runs on the Python standard library alone, with no packages to
install, and the page is one `index.html` with no build step. Please keep it
that way: a change that needs a new dependency is better raised as an issue
first.

## Before a pull request

Run the checks CI runs:

```sh
for m in config alerts store recon threatintel briefing security beszel cables; do python3 $m.py --self-test; done
python3 -m py_compile *.py
```

Keep a pull request to one change, and say in it what changed and why.
Update the README where the change matters to someone running Vantage, and
add a line under "Unreleased" in [CHANGELOG.md](CHANGELOG.md).

By contributing you agree that your work is released under the
[MIT licence](LICENSE).
