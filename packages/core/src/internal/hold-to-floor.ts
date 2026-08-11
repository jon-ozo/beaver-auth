// SPDX-FileCopyrightText: 2026 John Ozoemena
// SPDX-License-Identifier: Apache-2.0

export async function holdToFloor(
	responseFloorMs: number,
	start: number,
): Promise<void> {
	const elapsed = Date.now() - start
	const remaining = responseFloorMs - elapsed
	if (remaining > 0) {
		await new Promise((resolve) => setTimeout(resolve, remaining))
	}
}
