// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx_test

import (
	"fmt"

	"github.com/cB-Sigma/knx"
)

func ExampleParseDPT() {
	d, _ := knx.ParseDPT("DPST-9-1")
	b, _ := d.Encode(-30.0)
	v, _ := d.Decode(b)
	fmt.Printf("%s % x %v %s\n", d, b, v, d.Unit())
	// Output: 9.001 8a 24 -30 Cel
}

func ExampleParseGroupAddress() {
	for _, s := range []string{"1/2/3", "1/515", "2563"} {
		g, _ := knx.ParseGroupAddress(s)
		fmt.Println(g)
	}
	// Output:
	// 1/2/3
	// 1/2/3
	// 1/2/3
}

// Read the group addresses of a project's 0.xml (ParseETSProject takes
// the .knxproj export itself as well, password-protected or not) and turn
// them into points.
func ExampleParseETSProject() {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<KNX xmlns="http://knx.org/xml/project/21">
  <Project Id="P-0A1B">
    <Installations>
      <Installation Name="Home">
        <GroupAddresses>
          <GroupRanges>
            <GroupRange Id="P-0A1B-0_GR-1" Name="Building">
              <GroupRange Id="P-0A1B-0_GR-2" Name="Kitchen">
                <GroupAddress Id="P-0A1B-0_GA-1" Address="2305" Name="Ceiling light" DatapointType="DPST-1-1" />
                <GroupAddress Id="P-0A1B-0_GA-2" Address="2306" Name="Temperature" DatapointType="DPST-9-1" />
              </GroupRange>
            </GroupRange>
          </GroupRanges>
        </GroupAddresses>
      </Installation>
    </Installations>
  </Project>
</KNX>`
	p, err := knx.ParseETSProject([]byte(xml), "")
	if err != nil {
		fmt.Println(err)
		return
	}
	pts, _ := knx.ETSPoints(p, nil, "home")
	for _, pt := range pts {
		fmt.Println(pt.Device, pt.Name, pt.GroupAddress, pt.DPT, pt.Writable)
	}
	// Output:
	// kitchen ceiling-light 1/1/1 1.001 true
	// kitchen temperature 1/1/2 9.001 false
}
