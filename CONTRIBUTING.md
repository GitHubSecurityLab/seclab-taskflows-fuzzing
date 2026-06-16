# Contributing to seclab-taskflows-fuzzing

Thank you for your interest in contributing to this project! We welcome contributions of all kinds: bug reports, feature requests, documentation improvements, and code changes.

## Getting Started

1. Fork the repository and clone your fork locally.
2. Open the project in a GitHub Codespace or set up a local dev container (see `.devcontainer/`).
3. Create a virtual environment and install the project in development mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Build Instructions

This project uses [Hatch](https://hatch.pypa.io/) as its build system:

```bash
pip install hatch
hatch build
```

To run tests:

```bash
hatch run test
```

To run linting/type checks:

```bash
hatch run types:check
```

## Making Changes

1. Create a new branch for your changes: `git checkout -b my-feature`
2. Make your changes and write tests where appropriate.
3. Ensure all existing tests pass.
4. Commit your changes with clear, descriptive commit messages.
5. Push to your fork and open a Pull Request against the `main` branch.

## Coding Conventions

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines for Python code.
- Use type hints where possible.
- Keep YAML taskflow/prompt files well-documented with comments.
- C harness code should follow the AFL++ conventions for `LLVMFuzzerTestOneInput`.

## Project Structure

```
src/seclab_taskflows_fuzzing/
├── configs/         # Configuration files
├── dictionaries/    # Fuzzing dictionaries and custom mutators
├── mcp_servers/     # MCP server implementations (tools the agent calls)
├── personalities/   # Agent personality definitions
├── prompts/         # Prompt templates
├── taskflows/       # Taskflow YAML definitions (pipeline stages)
└── toolboxes/       # Toolbox definitions
```

## Reporting Bugs

Please open an issue on GitHub with:
- A clear description of the problem.
- Steps to reproduce the issue.
- Expected vs. actual behavior.
- Environment details (OS, Python version, etc.).

## Suggesting Features

Open an issue describing:
- The use case or problem you'd like to solve.
- Your proposed approach (if you have one).
- Any alternatives you've considered.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
