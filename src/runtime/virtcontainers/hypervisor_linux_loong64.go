// Copyright (c) 2021 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

func availableGuestProtection() (guestProtection, error) {
	return noneProtection, nil
}
