package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

type Features struct {
	Progs   map[string]bool     `json:"program_types"`
	Maps    map[string]bool     `json:"map_types"`
	Helpers map[string][]string `json:"helpers"`
}

func main() {
	probes := runProbes()

	compareProgs(probes)
	compareHelpers(probes)

}

func runProbes() Features {
	fmt.Println("Running bpftool -j feature ...")
	var features Features
	bpftool := exec.Command("bpftool", "-j", "feature", "probe", "full")
	out, err := bpftool.Output()
	if err != nil {
		os.Exit(1)
	}
	if err := json.Unmarshal(out, &features); err != nil {
		os.Exit(1)
	}
	return features
}

func compareProgs(probes Features) {
	fmt.Printf("\nComparing available program types ...\n")

	progLookup := createReverseProgLookup()

	for p, v := range probes.Progs {
		progType := sanitizeProgName(p)
		switch progType {
		case "LSM", "Extension", "StructOps", "Tracing":
			continue
		}

		err := features.HaveProgramType(progLookup[progType])

		if err != nil && v == true || err == nil && v == false {
			fmt.Printf("    API got different result for %s\n", progLookup[p])
		}
	}
}

func compareHelpers(probes Features) {
	fmt.Printf("\nComparing available helper functions ...\n")

	progLookup := createReverseProgLookup()
	helperLookup := createReverseHelperLookup()

	availableHelpers := make(map[ebpf.ProgramType]map[asm.BuiltinFunc]bool)
	for pt := ebpf.UnspecifiedProgram + 1; pt <= pt.Max(); pt++ {
		availableHelpers[pt] = make(map[asm.BuiltinFunc]bool)
	}

	for p, helpers := range probes.Helpers {
		progType := sanitizeProgName(p)
		switch progType {
		case "LSM", "Extension", "StructOps", "Tracing":
			continue
		}
		for _, h := range helpers {
			helperFunc := sanitizeHelperName(h)
			availableHelpers[progLookup[progType]][helperLookup[helperFunc]] = true
		}
	}

	for p, helpers := range availableHelpers {
		for h := asm.FnUnspec + 1; h <= h.Max(); h++ {
			err := features.HaveProgramHelper(p, h)
			expected := helpers[h]
			if err != nil && expected == true {
				fmt.Printf("    False negative: API got different result than bpftool for: %s/%s \n", p, h)
			}
			if err == nil && expected == false {
				fmt.Printf("    False positive: API got different result than bpftool for: %s/%s \n", p, h)
			}
		}
	}

}

func createReverseProgLookup() map[string]ebpf.ProgramType {
	progLookup := make(map[string]ebpf.ProgramType)

	for p := ebpf.UnspecifiedProgram; p <= p.Max(); p++ {
		progLookup[p.String()] = p
	}
	return progLookup
}

func createReverseMapLookup() map[string]ebpf.MapType {
	mapLookup := make(map[string]ebpf.MapType)

	for m := ebpf.UnspecifiedMap; m <= m.Max(); m++ {
		mapLookup[m.String()] = m
	}
	return mapLookup
}

func createReverseHelperLookup() map[string]asm.BuiltinFunc {
	helperLookup := make(map[string]asm.BuiltinFunc)

	for h := asm.FnUnspec; h <= h.Max(); h++ {
		helperLookup[h.String()] = h
	}
	return helperLookup
}

func sanitizeProgName(progJSON string) string {
	prog := strings.TrimSuffix(progJSON, "_available_helpers")
	prog = strings.TrimSuffix(prog, "_prog_type")
	prog = strings.TrimPrefix(prog, "have_")

	splitted := strings.Split(prog, "_")
	for i := range splitted {
		splitted[i] = strings.Title(splitted[i])
		if len(splitted[i]) == 3 {
			switch splitted[i] {
			case "Ops", "Raw", "Msg", "Out":
			default:
				splitted[i] = strings.ToUpper(splitted[i])
			}
		}

		if splitted[i] == "EXT" {
			splitted[i] = "Extension"
		} else if splitted[i] == "Cgroup" {
			splitted[i] = "CGroup"
		} else if splitted[i] == "Seg6local" {
			splitted[i] = "Seg6Local"
		} else if splitted[i] == "Tracepoint" && i == 0 {
			splitted[i] = "TracePoint"
		}
	}

	return strings.Join(splitted, "")
}

func sanitizeMapName(mapJSON string) string {
	return ""
}

func sanitizeHelperName(helperJSON string) string {
	helper := strings.Replace(helperJSON, "bpf", "fn", 1)

	splitted := strings.Split(helper, "_")
	for i := range splitted {
		splitted[i] = strings.Title(splitted[i])
	}

	return strings.Join(splitted, "")
}
