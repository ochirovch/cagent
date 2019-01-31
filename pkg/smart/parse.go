package smart

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

type ataSmartAttributes struct {
	Table []struct {
		ID         int    `json:"id"`
		Name       string `json:"name"`
		Value      int    `json:"value"`
		Worst      int    `json:"worst"`
		Thresh     int    `json:"thresh"`
		WhenFailed string `json:"when_failed"`
	} `json:"table"`
}

type parseResult struct {
	Smartctl struct {
		Status   int `json:"exit_status"`
		Messages []struct {
			String string `json:"string"`
		}
	} `json:"smartctl"`
	Device struct {
		Name     string `json:"name"`
		InfoName string `json:"info_name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`

	ModelName          string  `json:"model_name"`
	SerialNumber       string  `json:"serial_number"`
	ModelFamily        *string `json:"model_family"`
	FirmwareVersion    string  `json:"firmware_version"`
	InSmartctlDatabase bool    `json:"in_smartctl_database"`

	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`

	Temperature *struct {
		Current float32 `json:"current"`
	} `json:"temperature"`

	PowerCycleCount *int `json:"power_cycle_count"`
	PowerOnTime     *struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`

	RotationRate      *int `json:"rotation_rate,omitempty"`
	LogicalBlockSize  *int `json:"logical_block_size,omitempty"`
	PhysicalBlockSize *int `json:"physical_block_size,omitempty"`

	UserCapacity *struct {
		Blocks int   `json:"blocks"`
		Bytes  int64 `json:"bytes"`
	} `json:"user_capacity"`

	ATAVersion *struct {
		String     string `json:"string"`
		MajorValue int    `json:"major_value"`
		MinorValue int    `json:"minor_value"`
	} `json:"ata_version"`

	SATAVersion *struct {
		String string `json:"string"`
		Value  int    `json:"value"`
	} `json:"sata_version"`

	InterfaceSpeed *struct {
		Max struct {
			SataValue      int    `json:"sata_value"`
			String         string `json:"string"`
			UnitsPerSecond int64  `json:"units_per_second"`
			BitsPerUnit    int64  `json:"bits_per_unit"`
		} `json:"max"`
	} `json:"interface_speed"`

	NVMESmartHealthInformationLog *struct {
		CriticalWarning         int   `json:"critical_warning"`
		Temperature             int   `json:"temperature"`
		AvailableSpare          int   `json:"available_spare"`
		AvailableSpareThreshold int   `json:"available_spare_threshold"`
		PercentageUsed          int   `json:"percentage_used"`
		DataUnitsRead           int64 `json:"data_units_read"`
		DataUnitsWritten        int64 `json:"data_units_written"`
		HostReads               int64 `json:"host_reads"`
		HostWrites              int64 `json:"host_writes"`
		ControllerBusyTime      int64 `json:"controller_busy_time"`
		PowerCycles             int   `json:"power_cycles"`
		PowerOnHours            int   `json:"power_on_hours"`
		UnsafeShutdowns         int   `json:"unsafe_shutdowns"`
		MediaErrors             int   `json:"media_errors"`
		NumErrLogEntries        int   `json:"num_err_log_entries"`
	} `json:"nvme_smart_health_information_log"`

	ATASmartData *struct {
		SelfTest struct {
			String string `json:"string"`
			Passed bool   `json:"passed"`
		} `json:"self_test"`
		Capabilities struct {
			ExecOfflineImmediateSupport bool `json:"exec_offline_immediate_supported"`
			OfflineIsAbortedUponNewCmd  bool `json:"offline_is_aborted_upon_new_cmd"`
			OfflineSurfaceScanSupported bool `json:"offline_surface_scan_supported"`
			SelfTestsSupported          bool `json:"self_tests_supported"`
			ConveyanceSelfTestSupported bool `json:"conveyance_self_test_supported"`
			SelectiveSelfTestSupported  bool `json:"selective_self_test_supported"`
			AttributeAutoSaveEnabled    bool `json:"attribute_autosave_enabled"`
			ErrorLoggingSupported       bool `json:"error_logging_supported"`
			GpLoggingSupported          bool `json:"gp_logging_supported"`
		}
	} `json:"ata_smart_data"`

	ATASmartAttributes *ataSmartAttributes `json:"ata_smart_attributes"`

	ATASmartSelectiveSelfTestLog *struct {
		Revision int `json:"revision"`

		Flags struct {
			ReminderScanEnabled bool `json:"reminder_scan_enabled"`
		} `json:"flags"`
		PowerUpScanResumeMinutes int `json:"power_up_scan_resume_minutes"`
	} `json:"ata_smart_selective_self_test_log"`
}

var smartctlVersionRegexp *regexp.Regexp

func init() {
	smartctlVersionRegexp = regexp.MustCompile(`^smartctl\s(\d.\d)\s(\w|\W)+$`)
}

func DetectTools() error {
	buildStr, err := checkTools()
	if err != nil {
		return err
	}

	return smartctlIsSupportedVersion(buildStr)
}

// Parse detect hardware disks and parse their S.M.A.R.T
func Parse() (interface{}, []error) {
	rawDisksOutput, err := detectDisks()
	if err != nil {
		return nil, []error{err}
	}

	var disks []string
	if disks, err = parseDisks(rawDisksOutput); err != nil {
		return nil, []error{err}
	}

	var errs []error
	var jsonOutput []string
	if jsonOutput, err = smartCtlRun(disks); err != nil {
		errs = append(errs, err)
	}

	result, parseErrors := smartCtlParse(jsonOutput)

	return result, append(errs, parseErrors...)
}

func smartCtlRun(disks []string) ([]string, error) {
	var result []string

	var errStr string

	for _, disk := range disks {
		cmd := smartctlPrepare(disk)
		buf := &bytes.Buffer{}
		cmd.Stdout = bufio.NewWriter(buf)

		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.ExitStatus() == 1 {
					errStr += buf.String() + "\n"

					continue
				}
			}
		}

		result = append(result, buf.String())
	}

	if errStr != "" {
		return result, errors.New("smart: " + errStr)
	}

	return result, nil
}

func smartCtlParse(raw []string) (interface{}, []error) {
	var parsedDisks []*parseResult

	var errs []error
	for _, r := range raw {
		res := &parseResult{}
		err := json.Unmarshal([]byte(r), res)
		if err != nil {
			errs = append(errs, err)
		} else {
			parsedDisks = append(parsedDisks, res)
		}
	}

	var marshaledDisks []interface{}

	for _, d := range parsedDisks {
		output := make(map[string]interface{})

		parseBase(output, d)

		switch d.Device.Protocol {
		case "NVMe":
		case "ATA":
			if d.ATASmartAttributes != nil {
				ata := make(map[string]interface{})
				parseATAAttributes(ata, d.ATASmartAttributes)
				output["ata"] = ata
			}
		default:
		}

		marshaledDisks = append(marshaledDisks, output)
	}

	return marshaledDisks, errs
}

func smartctlIsSupportedVersion(buildStr string) error {
	if !smartctlVersionRegexp.Match([]byte(buildStr)) {
		return errors.New("smart: couldn't detect smartctl version")
	}

	ver := smartctlVersionRegexp.FindAllStringSubmatch(buildStr, -1)

	tok := strings.Split(ver[0][1], ".")

	var major int
	var minor int
	var err error

	major, err = strconv.Atoi(tok[0])
	if err != nil {
		return fmt.Errorf("smart: parse smartctl version: %s", err)
	}

	minor, err = strconv.Atoi(tok[1])
	if err != nil {
		return fmt.Errorf("smart: parse smartctl version: %s", err)
	}

	if (major > 7) || ((major == 7) && (minor >= 0)) {
		return nil
	}
	return fmt.Errorf("smart: unsupported smartctl version. expected minimum [7.0], desired [%s]", ver[0][1])
}

func parseBase(output map[string]interface{}, d *parseResult) {
	output["device_name"] = d.Device.Name
	output["device_type"] = d.Device.Type
	output["device_protocol"] = d.Device.Protocol
	output["model_name"] = d.ModelName
	if d.ModelFamily != nil {
		output["model_family"] = *d.ModelFamily
	}
	output["serial_number"] = d.SerialNumber
	output["firmware_version"] = d.FirmwareVersion
	if d.PowerCycleCount != nil {
		output["power_cycle_count"] = *d.PowerCycleCount
	}

	if d.SmartStatus == nil {
		output["smart_status"] = "NOT AVAILABLE"
	} else if d.SmartStatus.Passed {
		output["smart_status"] = "PASSED"
	} else {
		output["smart_status"] = "FAILED"
	}

	if d.Temperature != nil {
		output["temperature"] = d.Temperature.Current
	}

	if d.PowerOnTime != nil {
		output["power_on_time_hours"] = d.PowerOnTime.Hours
	}

	if d.RotationRate == nil || ((d.RotationRate != nil) && (*d.RotationRate == 0)) {
		output["type_of"] = "SSD"
	} else {
		output["type_of"] = "HDD"
		output["rotation_rate"] = d.RotationRate
	}

	if d.InterfaceSpeed != nil {
		output["interface_speed_B"] = int64((d.InterfaceSpeed.Max.BitsPerUnit * d.InterfaceSpeed.Max.UnitsPerSecond) / 8)
	}
}

func parseATAAttributes(output map[string]interface{}, d *ataSmartAttributes) {
	for _, at := range d.Table {
		output["attribute."+strconv.Itoa(at.ID)+".name"] = at.Name
		output["attribute."+strconv.Itoa(at.ID)+".value"] = at.Value
		output["attribute."+strconv.Itoa(at.ID)+".worst"] = at.Worst
		output["attribute."+strconv.Itoa(at.ID)+".thresh"] = at.Thresh
		output["attribute."+strconv.Itoa(at.ID)+".when_failed"] = at.WhenFailed
	}
}
