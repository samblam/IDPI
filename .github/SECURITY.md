# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email. You should receive a response within 48 hours.
If the issue is confirmed, we will release a patch as soon as possible depending on
the complexity of the issue.

Please include the following information in your report:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Security Best Practices

When deploying this project:

1. **Never commit secrets** - Use environment variables or Azure Key Vault
2. **Use HTTPS** - Always use TLS/SSL for API endpoints
3. **API Key Rotation** - Regularly rotate API keys
4. **Rate Limiting** - Ensure rate limiting is properly configured
5. **Input Validation** - All user inputs are validated (parameterized queries used)
6. **Dependencies** - Keep all dependencies up to date (Dependabot enabled)
7. **Monitoring** - Enable Azure Monitor for security alerts

## Known Security Considerations

- This project uses Azure OpenAI API keys which should be kept secure
- Redis cache does not have authentication enabled in the example docker-compose
  (add AUTH for production)
- Cosmos DB emulator uses a well-known key for local development only
  (use secure keys for production)
