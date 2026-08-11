// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

export interface OAuthProviderConfig {
	clientId: string
	clientSecret: string
	redirectUri: string
	authorizationUrl: string
	tokenUrl: string
	userProfileUrl?: string // Optional: Endpoint to extract provider payload profiles

	/**
	 * Timeout (ms) applied to the token exchange and profile fetch requests.
	 * A hung third-party provider shouldn't be able to hang the caller's
	 * request indefinitely — especially costly in serverless, where hung
	 * requests burn billed compute until the platform's own hard timeout
	 * intervenes.
	 * @default 10000
	 */
	requestTimeoutMs?: number
}

export interface AuthorizationUriResult {
	url: string
	state: string
	codeVerifier: string
}

export interface OAuthTokenResponse {
	access_token: string
	token_type: string
	expires_in?: number
	refresh_token?: string
	scope?: string
	[key: string]: unknown
}

export interface ValidateCodeOptions {
	code: string
	codeVerifier: string
	state: string
	expectedState: string
}

export interface StandardProfileOutput {
	providerId: string
	email: string
	avatarUrl?: string
	raw: Record<string, unknown>
}

export class OAuthEngine {
	private static readonly DEFAULT_REQUEST_TIMEOUT_MS = 10_000

	/**
	 * Generates tracking secrets and a structural PKCE redirection URL target.
	 */
	public generateAuthorizationUri(
		config: OAuthProviderConfig,
		scopes: string[],
	): AuthorizationUriResult {
		const state = randomBytes(32).toString('hex')
		const codeVerifier = randomBytes(32).toString('base64url')

		const codeChallenge = createHash('sha256')
			.update(codeVerifier)
			.digest('base64url')

		const urlParams = new URLSearchParams({
			response_type: 'code',
			client_id: config.clientId,
			redirect_uri: config.redirectUri,
			scope: scopes.join(' '),
			state: state,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
		})

		return {
			url: `${config.authorizationUrl}?${urlParams.toString()}`,
			state,
			codeVerifier,
		}
	}

	/**
	 * Safely exchanges an inbound callback code for authentication tokens.
	 * Enforces constant-time state tracking, request timeouts, and validates
	 * the response actually contains a usable access token before returning.
	 */
	public async validateAuthorizationCode(
		config: OAuthProviderConfig,
		options: ValidateCodeOptions,
	): Promise<OAuthTokenResponse> {
		if (!options.state || !options.expectedState) {
			throw new Error(
				'OAuth validation failed: Missing required verification parameters.',
			)
		}

		const stateBuffer = Buffer.from(options.state, 'utf8')
		const expectedBuffer = Buffer.from(options.expectedState, 'utf8')

		if (
			stateBuffer.length !== expectedBuffer.length ||
			!timingSafeEqual(stateBuffer, expectedBuffer)
		) {
			throw new Error('OAuth validation failed: CSRF state mismatch.')
		}

		const bodyParams = new URLSearchParams({
			code: options.code,
			redirect_uri: config.redirectUri,
			grant_type: 'authorization_code',
			code_verifier: options.codeVerifier,
		})

		const credentialsBase64 = Buffer.from(
			`${config.clientId}:${config.clientSecret}`,
		).toString('base64')

		const response = await this.fetchWithTimeout(
			config.tokenUrl,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Accept: 'application/json',
					Authorization: `Basic ${credentialsBase64}`,
				},
				body: bodyParams.toString(),
			},
			config.requestTimeoutMs ?? OAuthEngine.DEFAULT_REQUEST_TIMEOUT_MS,
			'Token exchange',
		)

		if (!response.ok) {
			let errorDetails: string

			try {
				const errJson = (await response.json()) as Record<string, unknown>
				errorDetails = JSON.stringify(errJson)
			} catch {
				const rawText = await response.text()
				errorDetails = rawText.slice(0, 200) || response.statusText
			}

			throw new Error(
				`OAuth protocol validation failed (${response.status}): ${errorDetails}`,
			)
		}

		let data: Record<string, unknown>

		try {
			data = (await response.json()) as Record<string, unknown>
		} catch {
			throw new Error(
				'OAuth token exchange failed: provider returned a 2xx response ' +
					'that was not valid JSON.',
			)
		}

		if (typeof data.access_token !== 'string' || !data.access_token) {
			throw new Error(
				'OAuth token exchange failed: provider response is missing a ' +
					'usable access_token.',
			)
		}

		if (typeof data.token_type !== 'string' || !data.token_type) {
			throw new Error(
				'OAuth token exchange failed: provider response is missing token_type.',
			)
		}

		return data as OAuthTokenResponse
	}

	/**
	 * High-DX Utility: Automatically contacts provider nodes to pull and unify profile records.
	 */
	public async fetchProfile(
		accessToken: string,
		profileUrl: string,
		mapper: (raw: Record<string, unknown>) => {
			providerId: string
			email: string
			avatarUrl?: string
		},
		requestTimeoutMs?: number,
	): Promise<StandardProfileOutput> {
		const response = await this.fetchWithTimeout(
			profileUrl,
			{
				headers: {
					Authorization: `Bearer ${accessToken}`,
					Accept: 'application/json',
				},
			},
			requestTimeoutMs ?? OAuthEngine.DEFAULT_REQUEST_TIMEOUT_MS,
			'Profile fetch',
		)

		if (!response.ok) {
			throw new Error(
				`Failed to retrieve social user profile payload metrics: ${response.statusText}`,
			)
		}

		let rawData: Record<string, unknown>

		try {
			rawData = (await response.json()) as Record<string, unknown>
		} catch {
			throw new Error(
				'Profile fetch failed: provider returned a 2xx response that was ' +
					'not valid JSON.',
			)
		}

		let mapped: { providerId: string; email: string; avatarUrl?: string }

		try {
			mapped = mapper(rawData)
		} catch (err) {
			throw new Error(
				`Profile fetch failed: mapper function threw while parsing the ` +
					`provider's response shape. Cause: ${
						err instanceof Error ? err.message : String(err)
					}`,
			)
		}

		if (!mapped.providerId || !mapped.email) {
			throw new Error(
				'Profile fetch failed: mapper did not produce a providerId and email.',
			)
		}

		return {
			...mapped,
			raw: rawData,
		}
	}

	/**
	 * fetch() wrapper enforcing a hard timeout via AbortController. A hung
	 * provider (outage, network partition, slow response) can otherwise hang
	 * the caller indefinitely — costly in any deployment, and directly
	 * billed compute in serverless.
	 */
	private async fetchWithTimeout(
		url: string,
		init: RequestInit,
		timeoutMs: number,
		label: string,
	): Promise<Response> {
		const controller = new AbortController()
		const timer = setTimeout(() => controller.abort(), timeoutMs)

		try {
			return await fetch(url, { ...init, signal: controller.signal })
		} catch (err) {
			if (err instanceof Error && err.name === 'AbortError') {
				throw new Error(`${label} timed out after ${timeoutMs}ms.`)
			}
			throw err
		} finally {
			clearTimeout(timer)
		}
	}
}
