# Contributing to vulnq

We welcome contributions to vulnq! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct, which promotes a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

- Check if the issue already exists in the [issue tracker](https://github.com/SemClone/vulnq/issues)
- Provide a clear description of the problem
- Include steps to reproduce the issue
- Specify your environment (OS, Python version, vulnq version)

### Suggesting Enhancements

- Open an issue describing the enhancement
- Explain the use case and benefits
- Provide examples if possible

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add or update tests as needed
5. Ensure all tests pass (`pytest`)
6. Update documentation if needed
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/SemClone/vulnq.git
   cd vulnq
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install in development mode:
   ```bash
   pip install -e .[dev]
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=vulnq tests/
```

Run specific tests:
```bash
pytest tests/test_utils.py -v
```

## Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run all checks:
```bash
black vulnq/
isort vulnq/
flake8 vulnq/
mypy vulnq/
```

Or use pre-commit:
```bash
pre-commit run --all-files
```

## Documentation

- Update the README.md if you change functionality
- Add docstrings to all public functions and classes
- Update CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/) format

## Adding New Vulnerability Sources

To add support for a new vulnerability database:

1. Create a new client module in `vulnq/clients/`
2. Implement the client following the existing pattern
3. Add the source to `VulnerabilitySource` enum
4. Update the core query logic to use your client
5. Add tests for the new functionality
6. Update documentation

Example structure:
```python
# vulnq/clients/new_source.py
class NewSourceClient:
    async def query(self, identifier: str) -> List[Vulnerability]:
        # Implementation here
        pass
```

## Commit Messages

Follow these guidelines for commit messages:

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests when relevant

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create a git tag: `git tag v0.1.0`
4. Push tag: `git push origin v0.1.0`
5. GitHub Actions will automatically publish to PyPI

## Questions?

Feel free to open an issue or discussion on GitHub if you have questions about contributing.

Thank you for contributing to vulnq!