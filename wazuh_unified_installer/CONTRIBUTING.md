# Contributing to Wazuh Unified Installer
# Author: Rodrigo Marins Piaba (Fanaticos4tech)
# E-Mail: rodrigomarinsp@gmail.com / fanaticos4tech@gmail.com
# GitHub: rodrigomarinsp
# Instagram: @fanaticos4tech

Thank you for your interest in contributing to the Wazuh Unified Installer! This document provides guidelines and best practices for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Additional Resources](#additional-resources)

## Code of Conduct

This project adheres to a Code of Conduct that all participants are expected to follow. By participating, you are expected to uphold this code. Please report unacceptable behavior to [rodrigomarinsp@gmail.com](mailto:rodrigomarinsp@gmail.com).

## How Can I Contribute?

There are several ways to contribute to the project:

### 🐛 Reporting Bugs

- Check if the bug has already been reported in the GitHub Issues.
- Use the Bug Report template when creating an issue.
- Include as much detail as possible: steps to reproduce, expected behavior, actual behavior, logs, and environment details.

### 💡 Suggesting Features

- Check if the feature has already been suggested in GitHub Issues.
- Use the Feature Request template when creating an issue.
- Provide a clear description of the feature and the problem it solves.

### 💻 Code Contributions

- Start by looking at issues labeled "good first issue" or "help wanted".
- Comment on the issue to express your interest before starting work.
- Fork the repository and create a branch for your changes.
- Follow the coding standards and testing requirements.
- Submit a pull request with a clear description of the changes.

## Development Setup

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/yourusername/wazuh-unified-installer.git
   cd wazuh-unified-installer
   ```

2. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Install Development Dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r dev-requirements.txt  # Additional development tools
   ```

4. **Set Up Pre-commit Hooks** (optional but recommended):
   ```bash
   pre-commit install
   ```

## Pull Request Process

1. Update the README.md and documentation with details of changes if applicable.
2. Update the CHANGELOG.md with a description of your changes.
3. Ensure all tests pass and add new tests for new functionality.
4. Submit the pull request with a clear title and description.
5. Request a review from maintainers.
6. The PR will be merged after approval from the maintainers.

## Coding Standards

### Shell Scripts (Bash)

- Follow the [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html).
- Use shellcheck for linting.
- Include proper error handling.
- Add comments for complex logic.
- Use functions for reusable code.
- Include proper shebang lines: `#!/bin/bash`.

### Python

- Follow PEP 8 and use a linter (flake8, pylint).
- Use type hints (Python 3.6+).
- Document functions and classes with docstrings.
- Keep functions focused on a single responsibility.
- Use meaningful variable and function names.

### YAML/Configuration Files

- Use 2-space indentation.
- Include comments to explain complex configurations.
- Group related configurations together.
- Use consistent naming conventions.

## Testing

- Write unit tests for all new functionality.
- Ensure tests are running in CI/CD pipeline.
- For bash scripts, use frameworks like [bats](https://github.com/bats-core/bats-core).
- For Python code, use pytest.
- Test changes on different OS distributions.

To run tests:

```bash
# For Python tests
pytest

# For shell script tests
bats tests/
```

## Documentation

- Update documentation for any changes to functionality.
- Document all configuration options.
- Keep the README.md up to date.
- Add examples for new features.
- Use consistent formatting in Markdown files.

## Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [GitHub Flow Guide](https://guides.github.com/introduction/flow/)
- [Semantic Versioning](https://semver.org/)

---

Thank you for contributing to Wazuh Unified Installer! Your efforts help make this project better for everyone.
