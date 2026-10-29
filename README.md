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

For the 2026 Qloo Agentic Hackathon, judges can open the live demo at [https://interest-aware-learning-qloo.onrender.com/](https://interest-aware-learning-qloo.onrender.com/)

See [the hosted release guide](docs/HOSTED_RELEASE.md) for the hosting setup,
secret handling, judge-access steps, and accepted limitations. The HTTPS site
is the primary demonstration; local setup is not required to judge it.

## Try it: gardening and pH (judge walkthrough)

Open the [public learning studio](https://interest-aware-learning-qloo.onrender.com/).
No login or judge code is required. Use these three inputs to reproduce the
chemistry-to-gardening demonstration:

**1. Add interest:** Enter `gardening` and select **Add interest**.

**2. Paste educational material:** Copy the paragraph below into
**Paste educational material**.

> Acids and bases are substances that affect the concentration of hydrogen ions in an aqueous solution. The pH scale describes how acidic or basic a solution is. At 25°C, a pH of 7 is neutral, values below 7 are acidic, and values above 7 are basic. The pH scale is logarithmic: a change of one pH unit corresponds to a tenfold change in hydrogen ion activity. Acids can donate protons, while bases can accept them. When an acid reacts with a base, a neutralization reaction can occur. The resulting pH depends on the substances involved and their relative amounts.

**3. Ask a question:** Enter the following in
**What do you want help understanding?**

> Can you explain acids, bases, and the pH scale using examples from gardening? I want to understand why pH matters, not just memorize the definitions.

Select **Show a lesson**. A successful personalized result should explain
acids, bases, the logarithmic pH scale, and why different plants have different
soil-pH preferences, while distinguishing the supplied textbook facts from
independently researched gardening examples. The workflow uses Qloo for
cultural-interest discovery, Tavily for potential research sources, and OpenAI
for the explanation.

**What to look for:** a completed five-stage workflow, a clearly explained
lesson, an interest-specific example, and source/research references when
supported. The exact lesson wording, Qloo discoveries, and web references may
vary between runs. If external evidence cannot be safely used, the app can
return a labeled source-only fallback rather than invent citations.

The hosted demo has a shared generation allowance; please avoid repeated
submissions or rapid retries during evaluation.

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
