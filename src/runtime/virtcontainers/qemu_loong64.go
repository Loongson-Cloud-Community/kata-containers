// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"fmt"
	"time"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/types"
	govmmQemu "github.com/kata-containers/kata-containers/src/runtime/pkg/govmm/qemu"
)

type qemuLoongArch64 struct {
	// inherit from qemuArchBase, overwrite methods if needed
	qemuArchBase
}

const (
	defaultQemuPath           = "/usr/bin/qemu-system-loongarch64"
	defaultQemuMachineType    = QemuLoongson7a
	qmpMigrationWaitTimeout   = 5 * time.Second
	defaultQemuMachineOptions = "accel=kvm"
)

var kernelParams = []Param{
	{"console", "hvc0"},
	{"console", "hvc1"},
	{"rcupdate.rcu_expedited", "1"},
	{"reboot", "k"},
	{"cryptomgr.notests", ""},
	{"net.ifnames", "0"},
}

var supportedQemuMachine = govmmQemu.Machine{
	Type:    QemuLoongson7a,
	Options: defaultQemuMachineOptions,
}

// MaxQemuVCPUs returns the maximum number of vCPUs supported
func MaxQemuVCPUs() uint32 {
	return uint32(256)
}

func newQemuArch(config HypervisorConfig) (qemuArch, error) {
	machineType := config.HypervisorMachineType
	if machineType == "" {
		machineType = defaultQemuMachineType
	}

	if machineType != defaultQemuMachineType {
		return nil, fmt.Errorf("unrecognised machinetype: %v", machineType)
	}

	q := &qemuLoongArch64{
		qemuArchBase{
			qemuMachine:          supportedQemuMachine,
			qemuExePath:          defaultQemuPath,
			memoryOffset:         config.MemOffset,
			kernelParamsNonDebug: kernelParamsNonDebug,
			kernelParamsDebug:    kernelParamsDebug,
			kernelParams:         kernelParams,
			disableNvdimm:        config.DisableImageNvdimm,
			dax:                  true,
			protection:           noneProtection,
		},
	}

        if config.ConfidentialGuest {
		if err := q.enableProtection(); err != nil {
			return nil, err
		}

		if !q.qemuArchBase.disableNvdimm {
		        hvLogger.WithField("subsystem", "qemuLOONGARCH64").Warn("Nvdimm is not supported with confidential guest, disabling it.")
		        q.qemuArchBase.disableNvdimm = true
		}
        }

	q.handleImagePath(config)

	return q, nil
}

func (q *qemuLoongArch64) capabilities() types.Capabilities {
        var caps types.Capabilities

        // pseries machine type supports hotplugging drives
        if q.qemuMachine.Type == QemuPseries {
                caps.SetBlockDeviceHotplugSupport()
        }

        caps.SetMultiQueueSupport()
        caps.SetFsSharingSupport()

        return caps
}

func (q *qemuLoongArch64) bridges(number uint32) {
	q.Bridges = genericBridges(number, q.qemuMachine.Type)
}

func (q *qemuLoongArch64) cpuModel() string {
        return defaultCPUModel
}

func (q *qemuLoongArch64) memoryTopology(memoryMb, hostMemoryMb uint64, slots uint8) govmmQemu.Memory {
        return genericMemoryTopology(memoryMb, hostMemoryMb, slots, q.memoryOffset)
}

func (q *qemuLoongArch64) appendImage(ctx context.Context, devices []govmmQemu.Device, path string) ([]govmmQemu.Device, error) {
	if !q.disableNvdimm {
		return q.appendNvdimmImage(devices, path)
	}
	return q.appendBlockImage(ctx, devices, path)
}

func (q *qemuLoongArch64) enableProtection() error {
        q.protection, _ = availableGuestProtection()
        if q.protection != noneProtection {
                return fmt.Errorf("Protection %v is not supported on arm64", q.protection)
        }

        return nil
}
