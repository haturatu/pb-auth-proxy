# Git hooks

Enable the repository hooks once after cloning:

```sh
git config core.hooksPath .githooks
```

The pre-commit hook checks all Go files with `gofmt -l .`.
