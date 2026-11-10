# Kelan Reachability Analysis & Call Graph Architecture

Kelan static analysis uses AST-driven call graph modeling to compute function-level reachability for detected vulnerabilities and dependency symbols.

## Core Principle: Strict Three-State Verdicts
Every finding is classified into exactly one of three states:
1. `reachable`: Proven path exists from a known entrypoint (HTTP route, CLI command, or module execution).
2. `unreachable`: In closed, self-contained applications with static caller chains, dead code with zero call paths is flagged unreachable.
3. `unknown`: The analysis cannot mathematically prove or disprove reachability due to language dynamisms or open module boundaries.

> **CRITICAL INVARIANT:** *Unknown stays unknown; it is never rounded up to reachable or down to unreachable.*

---

## 1. Entrypoint Heuristics

### Python
- **HTTP / Web Framework Handlers**:
  - FastAPI / Starlette / Flask route decorators: `@app.get`, `@app.post`, `@app.put`, `@app.delete`, `@app.route`, `@router.*`, `@bp.route`, `@api_route`.
  - Celery & Background task decorators: `@celery.task`, `@app.task`.
- **CLI & Process Execution**:
  - `if __name__ == '__main__':` execution roots.
  - Functions named `main()`, `cli()`, `run()`, `handler()`, or `lambda_handler()`.
  - Click / Typer decorators: `@click.command()`, `@app.command()`.
- **Module Initialization**:
  - Top-level statements executed at `<module>` scope on import.

### JavaScript & TypeScript
- **HTTP Routers**:
  - Express, Koa, Fastify, and Hono routing calls: `app.get()`, `app.post()`, `router.use()`, `router.all()`, etc.
  - Next.js / Remix route handlers: exported `GET`, `POST`, `PUT`, `DELETE`, `default` page functions.
- **CLI & Server Lifecycle**:
  - Top-level script scope execution (`<top-level>`).
  - `app.listen()` callbacks and `process.argv` consumers.
- **Exported Symbols**:
  - ES6 `export function`, `export const`, CommonJS `module.exports`, and `exports.*`.

---

## 2. Call Graph Construction

1. **AST Node Extraction**: Tree-sitter parses the file into an abstract syntax tree. Function declarations, method definitions, arrow functions, and class methods are mapped to `FunctionNode` instances with line spans.
2. **Edge Construction**: Call expressions (`call` in Python, `call_expression` in JS/TS) inside each function body are resolved against local function definitions.
3. **Shortest Path Search**: A Breadth-First Search (BFS) is executed starting from all entrypoint nodes in parallel. The shortest path to the target function is recorded as an ordered list of function names (e.g. `["search_handler", "run_query"]`).

---

## 3. Analysis Limits & Fallback to `unknown`

Static analysis in dynamic scripting languages faces inherent boundaries where static call resolution is undecidable. When any of the following boundaries are encountered, the engine assigns `verdict: unknown` and records the limiting condition:

### A. Dynamic Dispatch & Reflection
- **Python**:
  - `getattr(obj, name)(*args)`
  - `globals()[name]()` / `locals()[name]()`
  - `eval()` / `exec()` / `__import__()`
  - Dispatch dictionaries (e.g. `COMMAND_MAP = {"run": execute_fn}`) where dictionary lookups are parameterized at runtime.
- **JavaScript / TypeScript**:
  - `window[funcName]()` / `globalThis[funcName]()`
  - `eval()` / `new Function()`
  - `Reflect.apply()`
  - Dynamic bracket indexing on objects: `handlers[action](req, res)`.

### B. Higher-Order Functions & Callbacks
- Passing functions as first-class arguments to third-party library routines (e.g. `executor.submit(worker_fn)`, `array.map(transform)`).
- Asynchronous task queues and event emitters (`emitter.on('event', listener)`).

### C. Open Library Boundaries
- If a file has no defined `main()`, CLI entrypoint, or HTTP handler, and behaves as an importable library module, public functions may be invoked by external consumers outside the scanned repository. Unreferenced public symbols in libraries are classified as `unknown`, not `unreachable`.

---

## 4. Layer Hand-Off

- `reachable` findings proceed to Layer 3 (LLM Triage) with call graph path evidence.
- `unknown` findings proceed to Layer 3 (LLM Triage) marked with unknown reachability for human-in-the-loop review.
- `unreachable` findings are preserved in reports as low-priority dead-code findings and skip LLM triage to minimize latency and token usage.
