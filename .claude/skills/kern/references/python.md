# Python sandboxes

Read this for `kern-sandbox` integration. Check the current [Python binding documentation](https://github.com/getkern/kern/blob/main/bindings/python/README.md) and installed SDK signature before choosing arguments. The Python package and Kern binary are versioned independently; inspect both.

The basic API is:

```python
from kern_sandbox import run_code

result = run_code("print(1)")
```

This illustrates the entry point, not a complete untrusted-execution configuration. Choose network-off behavior, a finite timeout, bounded output, and `require_limits=True` when enforced limits are required, using parameters supported by the installed SDK. For untrusted execution, explicitly set `deps_readonly=True` rather than relying on a default: the inspected README and changelog differed. Explicitly select mount permissions and expose only the required paths; memory caps do not bound workspace disk use.

For `Sandbox.run`, provide an argument list instead of composing a shell command from untrusted strings. Sandbox files can persist between calls while processes are fresh. Use `kernel()` only when a persistent interpreter is needed and account for shared execution state.

Treat the result's `fault` separately from an ordinary program exit. Startup can raise `SandboxError`; handle that separately from user code failure. Verify successful execution, a failing program, and the resource or network restriction relevant to the application. Never report isolation verified from an import-only test.
