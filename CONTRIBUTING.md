# Contributing to Thirsty-Lang

Thank you for your interest in contributing to Thirsty-Lang! We welcome contributions from the community.

## Code of Conduct

All contributors are expected to uphold a respectful, inclusive, and constructive environment. Harassment, discrimination, or any form of unprofessional behavior will not be tolerated.

When contributing, please:
- Be respectful and considerate of others
- Provide constructive feedback
- Focus on what is best for the community and the project
- Show empathy towards other community members
## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please email FounderOfTP@thirstysprojects.com with full details.

When reporting, please include:
- A clear description of the issue
- Steps to reproduce
- Expected behavior vs actual behavior
- Version information (output of `thirsty --version`)
- Any relevant error messages or stack traces

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run the test suite: `python -m pytest tests/ -v`
5. Commit your changes with clear commit messages
6. Push to your fork
7. Open a Pull Request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/TP-IAmSoThirsty/TP-Thirsty-Lang-Official.git
cd TP-Thirsty-Lang-Official

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional but recommended)
pre-commit install

# Verify installation
thirsty --version
thirst-of-gods --help
tarl --help
```

### Development Workflow

**Before committing:**

```bash
# Run tests
python -m pytest tests/ -v

# Format code (black)
black src/ tests/

# Lint code (ruff)
ruff check src/ tests/ --fix

# Type check
mypy src/utf/

# Or use pre-commit to run all checks
pre-commit run --all-files
```

**Pre-commit hooks** automatically run on every commit:
- Whitespace trimming and EOF fixes
- Black formatting
- Ruff linting
- pyproject.toml validation
- Console script entry point validation
- Version consistency check

**If hooks fail**, fix the issues and `git add` again before committing.

### Code Standards

- Python 3.11+ required
- Standard library only for core — no third-party runtime dependencies
- All water-metaphor keywords implemented exactly per spec
- Every AST node must carry span tracking
- Tests are required for all new features
- Default = DENY at every governance gate

### Pull Request Guidelines

- Keep pull requests focused on a single concern
- Add or update tests as needed
- Update documentation if the API or behavior changes
- Ensure all tests pass before requesting review

## Governance

Thirsty-Lang follows a default-DENY governance model. All changes are reviewed for:
- Security implications
- Backward compatibility
- Specification compliance
- Test coverage adequacy

## Questions?

If you have questions about contributing, please email FounderOfTP@thirstysprojects.com.

---

**Thirsty's Projects LLC**