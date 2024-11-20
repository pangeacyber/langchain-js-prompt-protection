# Prompt Protection for LangChain in JavaScript

An example JavaScript app that demonstrates integrating Pangea services into
LangChain to capture and filter what users are sending to LLMs:

- [Secure Audit Log][] — Create an event when a human prompt is received.
- [Redact][] — Remove sensitive information from prompts.
- [Domain Intel][] — Stop prompts with malicious domains from going to the LLM.
- [IP Intel][] — Stop prompts with malicious IP addresses from going to the LLM.
- [URL Intel][] — Stop prompts with malicious URLs from going to the LLM.

## Prerequisites

- Node.js v22.
- A [Pangea account][Pangea signup] with all of the above services enabled.
  - For Secure Audit Log, the AI Audit Log Schema Config should be used.
  - For Domain Intel, a default provider should be set.
- An [OpenAI API key][OpenAI API keys].

## Setup

```shell
git clone https://github.com/pangeacyber/langchain-js-prompt-protection.git
cd langchain-js-prompt-protection
npm install
cp .env.example .env
```

Fill in the values in `.env` and then the app can be run like so:

```shell
npm run exec -- --auditConfigId pci_1234567890 "What do you know about Michael Jordan the basketball player?"
```

A prompt like the above will be redacted:

```
What do you know about **** the basketball player?
```

To which the LLM's reply will be something like:

```
Could you please specify which basketball player you are referring to? There are
many players in the sport, and I’d be happy to provide information on any of
them!
```

Audit logs can be viewed at the [Secure Audit Log Viewer][].

[Secure Audit Log]: https://pangea.cloud/docs/audit/
[Secure Audit Log Viewer]: https://console.pangea.cloud/service/audit/logs
[Redact]: https://pangea.cloud/docs/redact/
[Domain Intel]: https://pangea.cloud/docs/domain-intel/
[IP Intel]: https://pangea.cloud/docs/ip-intel/
[URL Intel]: https://pangea.cloud/docs/url-intel/
[Pangea signup]: https://pangea.cloud/signup
[OpenAI API keys]: https://platform.openai.com/api-keys
