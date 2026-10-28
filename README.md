# Interest-Aware Learning

Interest-Aware Learning is a source-grounded educational explanation studio.
Learners provide their interests, educational source text, and a question. A
bounded workflow uses Qloo cultural associations to propose candidate contexts,
Tavily to research potentially useful connections, and an OpenAI model to write
an explanation that remains grounded in the learner-provided source.

The app distinguishes Qloo cultural candidates from factual evidence. Cultural
associations are not scientific proof, and a personalized example is not a
substitute for the original source. When a useful connection is not supported,
the workflow may use a neutral explanation.

## Hosted demo

For the 2026 Qloo Agentic Hackathon, judges can open the live demo at
https://interest-aware-learning-qloo.onrender.com/ without an access code
when public-demo mode is enabled. Live requests may incur API charges.
The hosted server uses an externally durable, atomic global request allowance
and a kill switch.

See [the hosted release guide](docs/HOSTED_RELEASE.md) for the hosting setup,
secret handling, judge-access steps, and accepted limitations. The HTTPS site
is the primary demonstration; local setup is not required to judge it.

## Local development

Python 3.12+; Python standard library only. With no provider keys, local demo:

```shell
python -B app.py --port 8765
```

Open http://127.0.0.1:8765/. The original local server binds only to loopback.
The public-hosting entry `python -B hosted_server.py` must be configured using
secrets and external durable quotas first. Never expose `app.py` directly on
an Internet port. Running offline tests makes no paid API requests:

```shell
python -B -m unittest discover -s tests -p 'test*.py' -q
```

## Security and privacy

The source text is authoritative for educational claims. User inputs are
untrusted, and the application does not render them as executable HTML.
The Qloo API receives selected learner interests; Tavily receives topic-derived
research searches; OpenAI receives the educational source and question,
interests and retrieved research context. Do not paste sensitive information.
Credentials belong in host secrets only. This is a bounded hackathon prototype,
not a production learning platform or a guarantee of pedagogical quality.

## License

MIT, see [LICENSE](LICENSE). Third-party services retain their own terms.
