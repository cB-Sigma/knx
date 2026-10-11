// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/cB-Sigma/knx"
)

// A project whose 0.xml leaves group object types out takes them from the
// product catalogue (the reference, else the object, also inside a module
// instance), else from the object size; disagreeing objects leave the
// group address without a type, objects of one main type give that main
// type; flags come from the catalogue.
// Covers: SIG-IPE-6710
func TestETSProductCatalogue(t *testing.T) {
	const app = "M-0001_A-0001-01-ABCD"
	files := map[string]string{
		"P-0001.signature": "",
		"P-0001/0.xml": `<KNX><Project><Installations><Installation Name="Cat">
<GroupAddresses><GroupRanges><GroupRange Name="R">
  <GroupAddress Id="P-0001-0_GA-1" Address="1" Name="from ref" />
  <GroupAddress Id="P-0001-0_GA-2" Address="2" Name="from object" />
  <GroupAddress Id="P-0001-0_GA-3" Address="3" Name="from size" />
  <GroupAddress Id="P-0001-0_GA-4" Address="4" Name="disagree" />
  <GroupAddress Id="P-0001-0_GA-5" Address="5" Name="same main" />
  <GroupAddress Id="P-0001-0_GA-6" Address="6" Name="module" />
</GroupRange></GroupRanges></GroupAddresses>
<Topology><Area><Line>
<DeviceInstance Id="P-0001-0_DI-1" Address="1" ProductRefId="M-0001_H-1_P-1" Hardware2ProgramRefId="M-0001_H-1_HP-0001-01-ABCD">
 <ComObjectInstanceRefs>
  <ComObjectInstanceRef RefId="O-1_R-1" Links="GA-1" />
  <ComObjectInstanceRef RefId="O-2_R-2" Links="GA-2" />
  <ComObjectInstanceRef RefId="O-3_R-3" Links="GA-3" />
  <ComObjectInstanceRef RefId="O-1_R-1" Links="GA-4 GA-5" />
  <ComObjectInstanceRef RefId="O-2_R-2" Links="GA-4" />
  <ComObjectInstanceRef RefId="O-4_R-4" Links="GA-5" />
  <ComObjectInstanceRef RefId="MD-1_M-1_MI-2_O-3-0_R-1" Links="GA-6" />
 </ComObjectInstanceRefs>
</DeviceInstance></Line></Area></Topology></Installation></Installations></Project></KNX>`,
		"M-0001/Hardware.xml": `<KNX><ManufacturerData><Manufacturer><Hardware><Hardware Id="M-0001_H-1">
<Hardware2Programs><Hardware2Program Id="M-0001_H-1_HP-0001-01-ABCD"><ApplicationProgramRef RefId="` + app + `" /></Hardware2Program></Hardware2Programs>
</Hardware></Hardware></Manufacturer></ManufacturerData></KNX>`,
		"M-0001/" + app + ".xml": `<KNX><ManufacturerData><Manufacturer><ApplicationPrograms><ApplicationProgram Id="` + app + `"><Static>
<ComObjects>
  <ComObject Id="` + app + `_O-1" ObjectSize="1 Bit" ReadFlag="Disabled" WriteFlag="Enabled" />
  <ComObject Id="` + app + `_O-2" DatapointType="DPST-9-1" ObjectSize="2 Bytes" ReadFlag="Enabled" WriteFlag="Disabled" />
  <ComObject Id="` + app + `_O-3" ObjectSize="4 Bit" />
  <ComObject Id="` + app + `_O-4" ObjectSize="1 Bit" />
</ComObjects>
<ComObjectRefs>
  <ComObjectRef Id="` + app + `_O-1_R-1" RefId="` + app + `_O-1" DatapointType="DPST-1-1" />
  <ComObjectRef Id="` + app + `_O-2_R-2" RefId="` + app + `_O-2" />
  <ComObjectRef Id="` + app + `_O-3_R-3" RefId="` + app + `_O-3" />
  <ComObjectRef Id="` + app + `_O-4_R-4" RefId="` + app + `_O-4" DatapointType="DPST-1-8" />
  <ComObjectRef Id="` + app + `_MD-1_O-3-0_R-1" RefId="` + app + `_MD-1_O-3-0" DatapointType="DPST-5-1" />
</ComObjectRefs>
</Static></ApplicationProgram></ApplicationPrograms></Manufacturer></ManufacturerData></KNX>`,
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()
	p, err := knx.ParseETSProject(buf.Bytes(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"from ref": "DPST-1-1", "from object": "DPST-9-1", "from size": "DPT-3", "disagree": "", "same main": "DPT-1", "module": "DPST-5-1"}
	for _, g := range p.GroupAddresses {
		if g.DPT != want[g.Name] {
			t.Errorf("%s: DPT %q, want %q", g.Name, g.DPT, want[g.Name])
		}
		if g.Name == "from object" && (g.Read == nil || !*g.Read || g.Write == nil || *g.Write) {
			t.Errorf("from object: flags from the catalogue %v %v", g.Read, g.Write)
		}
	}
	if len(p.GroupAddresses) != 6 {
		t.Errorf("%d group addresses", len(p.GroupAddresses))
	}
}
