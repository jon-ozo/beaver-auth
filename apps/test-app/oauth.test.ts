import { createHash } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { OAuthEngine } from '@beaver-auth/core'
import type { OAuthProviderConfig } from '@beaver-auth/core'

const CONFIG: OAuthProviderConfig = {
	clientId: 'client-123',
	clientSecret: 'secret-abc',
	redirectUri: 'https://myapp.example.com/callback',
	authorizationUrl: 'https://provider.example.com/authorize',
	tokenUrl: 'https://provider.example.com/token',
	userProfileUrl: 'https://provider.example.com/userinfo',
}

function mockResponse(overrides: Partial<Response> & { jsonBody?: unknown; textBody?: string }) {
	return {
		ok: overrides.ok ?? true,
		status: overrides.status ?? 200,
		statusText: overrides.statusText ?? 'OK',
		json: async () => {
			if (overrides.jsonBody === undefined) throw new Error('not json')
			return overrides.jsonBody
		},
		text: async () => overrides.textBody ?? '',
	} as Response
}

afterEach(() => {
	vi.unstubAllGlobals()
})

describe('OAuthEngine.generateAuthorizationUri', () => {
	it('builds a URL with PKCE S256 challenge correctly derived from the verifier', () => {
		const engine = new OAuthEngine()
		const result = engine.generateAuthorizationUri(CONFIG, ['openid', 'email'])

		const url = new URL(result.url)
		expect(url.origin + url.pathname).toBe(CONFIG.authorizationUrl)
		expect(url.searchParams.get('response_type')).toBe('code')
		expect(url.searchParams.get('client_id')).toBe(CONFIG.clientId)
		expect(url.searchParams.get('redirect_uri')).toBe(CONFIG.redirectUri)
		expect(url.searchParams.get('scope')).toBe('openid email')
		expect(url.searchParams.get('code_challenge_method')).toBe('S256')
		expect(url.searchParams.get('state')).toBe(result.state)

		const expectedChallenge = createHash('sha256')
			.update(result.codeVerifier)
			.digest('base64url')
		expect(url.searchParams.get('code_challenge')).toBe(expectedChallenge)
	})

	it('generates a fresh, high-entropy state and codeVerifier on every call', () => {
		const engine = new OAuthEngine()
		const a = engine.generateAuthorizationUri(CONFIG, [])
		const b = engine.generateAuthorizationUri(CONFIG, [])

		expect(a.state).not.toBe(b.state)
		expect(a.codeVerifier).not.toBe(b.codeVerifier)
		expect(a.state).toMatch(/^[0-9a-f]{64}$/)
	})
})

describe('OAuthEngine.validateAuthorizationCode', () => {
	it('rejects a state/expectedState mismatch (CSRF protection)', async () => {
		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'auth-code',
				codeVerifier: 'verifier',
				state: 'state-a',
				expectedState: 'state-b',
			}),
		).rejects.toThrow(/CSRF state mismatch/)
	})

	it('rejects missing state parameters', async () => {
		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'auth-code',
				codeVerifier: 'verifier',
				state: '',
				expectedState: 'state-b',
			}),
		).rejects.toThrow(/Missing required verification parameters/)
	})

	it('sends a correctly-formed token request and returns the parsed response', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			mockResponse({
				jsonBody: { access_token: 'at-123', token_type: 'Bearer', expires_in: 3600 },
			}),
		)
		vi.stubGlobal('fetch', fetchMock)

		const engine = new OAuthEngine()
		const result = await engine.validateAuthorizationCode(CONFIG, {
			code: 'auth-code',
			codeVerifier: 'verifier-xyz',
			state: 'same-state',
			expectedState: 'same-state',
		})

		expect(result).toEqual({ access_token: 'at-123', token_type: 'Bearer', expires_in: 3600 })

		expect(fetchMock).toHaveBeenCalledTimes(1)
		const [url, init] = fetchMock.mock.calls[0]
		expect(url).toBe(CONFIG.tokenUrl)
		expect(init.method).toBe('POST')
		expect(init.headers['Content-Type']).toBe('application/x-www-form-urlencoded')

		const expectedBasic = Buffer.from(`${CONFIG.clientId}:${CONFIG.clientSecret}`).toString(
			'base64',
		)
		expect(init.headers['Authorization']).toBe(`Basic ${expectedBasic}`)

		const body = new URLSearchParams(init.body)
		expect(body.get('code')).toBe('auth-code')
		expect(body.get('code_verifier')).toBe('verifier-xyz')
		expect(body.get('grant_type')).toBe('authorization_code')
	})

	it('throws with the parsed JSON error body when the provider returns a non-2xx JSON error', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(
				mockResponse({
					ok: false,
					status: 400,
					jsonBody: { error: 'invalid_grant' },
				}),
			),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'bad-code',
				codeVerifier: 'v',
				state: 's',
				expectedState: 's',
			}),
		).rejects.toThrow(/invalid_grant/)
	})

	it('falls back to raw text when the non-2xx error body is not valid JSON', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(
				mockResponse({
					ok: false,
					status: 502,
					statusText: 'Bad Gateway',
					textBody: 'upstream gateway error',
				}),
			),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'c',
				codeVerifier: 'v',
				state: 's',
				expectedState: 's',
			}),
		).rejects.toThrow(/upstream gateway error/)
	})

	it('rejects a 2xx response missing access_token', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(mockResponse({ jsonBody: { token_type: 'Bearer' } })),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'c',
				codeVerifier: 'v',
				state: 's',
				expectedState: 's',
			}),
		).rejects.toThrow(/missing a usable access_token/)
	})

	it('rejects a 2xx response missing token_type', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(mockResponse({ jsonBody: { access_token: 'at-123' } })),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'c',
				codeVerifier: 'v',
				state: 's',
				expectedState: 's',
			}),
		).rejects.toThrow(/missing token_type/)
	})

	it('rejects a 2xx response that is not valid JSON', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(mockResponse({})))

		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(CONFIG, {
				code: 'c',
				codeVerifier: 'v',
				state: 's',
				expectedState: 's',
			}),
		).rejects.toThrow(/not valid JSON/)
	})

	it('times out and throws a clear error if the provider hangs past requestTimeoutMs', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockImplementation((_url: string, init: RequestInit) => {
				return new Promise((_resolve, reject) => {
					init.signal?.addEventListener('abort', () => {
						const err = new Error('The operation was aborted')
						err.name = 'AbortError'
						reject(err)
					})
				})
			}),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.validateAuthorizationCode(
				{ ...CONFIG, requestTimeoutMs: 20 },
				{ code: 'c', codeVerifier: 'v', state: 's', expectedState: 's' },
			),
		).rejects.toThrow(/timed out after 20ms/)
	})
})

describe('OAuthEngine.fetchProfile', () => {
	const mapper = (raw: Record<string, unknown>) => ({
		providerId: String(raw.id),
		email: String(raw.email),
		avatarUrl: raw.picture ? String(raw.picture) : undefined,
	})

	it('fetches with a Bearer header and returns the mapped profile plus raw data', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			mockResponse({ jsonBody: { id: 'p-1', email: 'user@example.com', picture: 'x.png' } }),
		)
		vi.stubGlobal('fetch', fetchMock)

		const engine = new OAuthEngine()
		const result = await engine.fetchProfile('access-token-abc', CONFIG.userProfileUrl!, mapper)

		expect(result.providerId).toBe('p-1')
		expect(result.email).toBe('user@example.com')
		expect(result.raw).toEqual({ id: 'p-1', email: 'user@example.com', picture: 'x.png' })

		const [url, init] = fetchMock.mock.calls[0]
		expect(url).toBe(CONFIG.userProfileUrl)
		expect(init.headers['Authorization']).toBe('Bearer access-token-abc')
	})

	it('throws on a non-ok response', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(mockResponse({ ok: false, statusText: 'Forbidden' })),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.fetchProfile('token', CONFIG.userProfileUrl!, mapper),
		).rejects.toThrow(/Forbidden/)
	})

	it('wraps a throwing mapper with a clear error, without leaking the raw exception type', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(mockResponse({ jsonBody: { weird: 'shape' } })),
		)

		const engine = new OAuthEngine()
		const throwingMapper = () => {
			throw new Error('cannot read id of undefined')
		}

		await expect(
			engine.fetchProfile('token', CONFIG.userProfileUrl!, throwingMapper as any),
		).rejects.toThrow(/mapper function threw/)
	})

	it('rejects a mapper result missing providerId or email', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(mockResponse({ jsonBody: { id: '', email: '' } })),
		)

		const engine = new OAuthEngine()
		await expect(
			engine.fetchProfile('token', CONFIG.userProfileUrl!, mapper),
		).rejects.toThrow(/did not produce a providerId and email/)
	})
})
