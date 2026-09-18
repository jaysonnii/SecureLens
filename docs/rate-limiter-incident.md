# The rate limiter that ran too late

## What the docs said

SecureLens accepts log uploads at `POST /upload` with no authentication. Before deploying it publicly I added a per-IP rate limiter, and documented it in three places as rejecting requests before the request body was read.

That claim was false for about a week. Every test passed the entire time.

## Why I doubted it

The limiter was wired as a FastAPI route dependency:

```python
@router.post(
    "/upload",
    dependencies=[Depends(enforce_rate_limit)],
)
async def upload_file(file: UploadFile = File(...)):
```

Reading that back later, the ordering bothered me. The endpoint declares a `File(...)` parameter, which means FastAPI has to parse the multipart body to populate it. Dependencies are resolved during that same request preparation step. Nothing in the code says which happens first.

If the body is parsed first, a rate-limited client still uploads its entire payload before receiving a 429. The limiter stops the analyzer from running, which is worth something, but it does nothing about the bandwidth or the disk spooling, and that is most of what a rate limit on an upload endpoint is for.

I could have read the FastAPI source to settle it. I decided to measure instead, because what I wanted to know was what the running application actually did, not what the framework's code implied it should do.

## The probe

Starlette applications are callables taking `scope`, `receive`, and `send`. The body only arrives when the application awaits `receive()`. So whether the body was read is directly observable: wrap `receive` and record whether it was ever called.

```python
async def test_rate_limited_upload_is_rejected_before_the_body_is_read():
    received = False

    async def receive():
        nonlocal received
        received = True
        return {"type": "http.request", "body": b"", "more_body": False}

    # exhaust the limit, then drive one more request through the app
    ...
    assert status == 429
    assert not received, "body was read before the limit was enforced"
```

The assertion failed. `received` was `True`. The body had been consumed before the 429 was produced.

## The fix

Enforcement moved out of the dependency graph and into ASGI middleware, which runs before routing and therefore before any body parsing:

```python
class RateLimitMiddleware:
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and _should_check(scope):
            request = Request(scope)
            try:
                rate_limiter.check(client_key(request))
            except RateLimitExceeded as error:
                await _send_429(send, error.retry_after)
                return          # receive is never awaited
        await self._app(scope, receive, send)
```

It is registered inside the CORS middleware so a 429 still carries CORS headers. The probe stayed as a regression test: `test_rate_limited_upload_is_rejected_before_the_body_is_read` in `backend/tests/test_upload_rate_limit_lifecycle.py`. It is the only test in the suite asserting something about *when* the limiter runs rather than *what* it returns, and the only one that would catch this regressing.

## What I take from it

**The bug was invisible from outside.** Correct status codes, correct `Retry-After` headers, correct per-IP counts, every functional test green. The behaviour differed only in a property no ordinary test observes. If I had not gone looking, nothing would have told me.

**Documentation is a claim, not a record.** I wrote "checked before the request body is read" because it was what I intended to build, and then it sat there unverified across three files. When I first suspected it was wrong but could not yet prove it, I removed the sentence from all three rather than leave an unverified security property in writing. Small thing, right instinct.

**Measure the system, not the source.** Reading the framework's code would probably have got me the right answer. Instrumenting the real request path got me a test, which is worth more, because the answer stays checked.

## Related

- Limiter introduced: [#30](https://github.com/jaysonnii/SecureLens/pull/30)
- Thread safety, and removal of the unverified claim: [#32](https://github.com/jaysonnii/SecureLens/pull/32)
- Moved to middleware: [#33](https://github.com/jaysonnii/SecureLens/pull/33)
