// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { normalizePayload, PayloadPolicy } from './normalize-payload.js'
import { NormalizeOptions } from './normalize-payload.js'

export type JwtOptions = Pick<
	NormalizeOptions,
	'maxDepth' | 'maxNodes' | 'policy'
>

export function normalizeJwtPayload(
	payload: Record<string, unknown>,
	options: JwtOptions,
) {
	const normalizedJwtPayload = normalizePayload(payload, {
		maxDepth: options.maxDepth,
		maxNodes: options.maxNodes,
		policy: PayloadPolicy.Jwt,
	})

	return normalizedJwtPayload
}
