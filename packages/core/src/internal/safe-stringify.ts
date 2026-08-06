// Redact any key that looks sensitive before it ever reaches a log line — this is a
// generic dispatcher and payload is `unknown`, so it can't assume a shape,
// only pattern-match on common sensitive key names.
const SENSITIVE_KEY_PATTERN = /token|password|secret|hash|credential/i

export function safeStringify(payload: unknown): string {
	try {
		return JSON.stringify(payload, (key, value) =>
			SENSITIVE_KEY_PATTERN.test(key) ? '[redacted]' : value,
		)
	} catch {
		return '[unserializable payload]'
	}
}
