// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes } from 'node:crypto'

const TOKEN_BYTE_SIZE = 32
const HASH_ALG = 'sha256'

export function generateSecureToken(): string {
	return randomBytes(TOKEN_BYTE_SIZE).toString('hex')
}

export function hashSecureToken(rawToken: string): string {
	return createHash(HASH_ALG).update(rawToken).digest('hex')
}
