// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package knx

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// The product catalogue inside a project export. A device instance in
// 0.xml names its product (ProductRefId, whose part before the first "_"
// is the manufacturer folder M-xxxx) and its hardware-to-program link
// (Hardware2ProgramRefId). M-xxxx/Hardware.xml maps that link to an
// application program id, and M-xxxx/<program id>.xml defines the
// program's group objects (ComObject) and their references (ComObjectRef,
// whose RefId names the ComObject), each optionally with a datapoint type
// and flags. A ComObjectInstanceRef's RefId is the program id, "_", and
// the reference's own part (older ETS 4 exports give the full id); module
// instances are reduced to the module definition, the last submodule and
// the object part. These layout facts were read from xknxproject 3.10.0
// (GPL-2.0-only; loader/hardware_loader.py, application_program_loader.py,
// util.py strip_module_instance, models.py); no code was taken. The
// manufacturer folders sit outside the protected inner zip, so the
// catalogue is read for protected exports too.

type catObject struct {
	ref         string // ComObjectRef: the ComObject it refers to
	size        string
	dpt         string
	read, write *bool
}

type appProgram struct {
	refs, objs map[string]catObject
}

type catalogue struct {
	files map[string]*zip.File
	hw    map[string]map[string]string // manufacturer → hardware2program id → program id
	apps  map[string]*appProgram
}

func (c *catalogue) read(name string) []byte {
	f := c.files[name]
	if f == nil {
		return nil
	}
	b, err := readZipEntry(f, nil)
	if err != nil {
		return nil
	}
	return b
}

func (c *catalogue) hardware(m string) map[string]string {
	if h, ok := c.hw[m]; ok {
		return h
	}
	h := map[string]string{}
	c.hw[m] = h
	data := c.read(m + "/Hardware.xml")
	if data == nil {
		return h
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	var cur string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			switch se.Name.Local {
			case "Hardware2Program":
				cur, _ = attr(se, "Id")
			case "ApplicationProgramRef":
				if r, ok := attr(se, "RefId"); ok && cur != "" {
					h[cur] = r
				}
			}
		}
	}
	return h
}

func (c *catalogue) program(m, id string) *appProgram {
	if a, ok := c.apps[id]; ok {
		return a
	}
	a := &appProgram{refs: map[string]catObject{}, objs: map[string]catObject{}}
	c.apps[id] = a
	data := c.read(m + "/" + id + ".xml")
	if data == nil {
		return a
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || (se.Name.Local != "ComObject" && se.Name.Local != "ComObjectRef") {
			continue
		}
		oid, _ := attr(se, "Id")
		d, _ := attr(se, "DatapointType")
		o := catObject{dpt: firstDPT(d), read: flag(attr(se, "ReadFlag")), write: flag(attr(se, "WriteFlag"))}
		o.size, _ = attr(se, "ObjectSize")
		if se.Name.Local == "ComObjectRef" {
			o.ref, _ = attr(se, "RefId")
			a.refs[oid] = o
		} else {
			a.objs[oid] = o
		}
	}
	return a
}

// stripModule reduces a module instance reference to the module
// definition, the submodule just before the object, and the object part.
func stripModule(ref string) string {
	parts := strings.Split(ref, "_")
	at := -1
	for i, p := range parts {
		if strings.HasPrefix(p, "O-") {
			at = i
			break
		}
	}
	if at <= 0 {
		return ref
	}
	var out []string
	if strings.HasPrefix(parts[0], "MD-") {
		out = append(out, parts[0])
	}
	if strings.HasPrefix(parts[at-1], "SM-") {
		out = append(out, parts[at-1])
	}
	return strings.Join(append(out, parts[at:]...), "_")
}

// fill completes a group object's type and flags from the catalogue.
func (c *catalogue) fill(o *comObject) {
	m, _, _ := strings.Cut(o.product, "_")
	if !strings.HasPrefix(m, "M-") {
		m, _, _ = strings.Cut(o.h2p, "_")
	}
	if !strings.HasPrefix(m, "M-") || o.refID == "" {
		return
	}
	app := c.hardware(m)[o.h2p]
	if app == "" {
		return
	}
	prog := c.program(m, app)
	refID := o.refID
	if !strings.HasPrefix(refID, app+"_") {
		refID = app + "_" + stripModule(refID)
	}
	ref, ok := prog.refs[refID]
	if !ok {
		return
	}
	for _, src := range []catObject{ref, prog.objs[ref.ref]} {
		if o.dpt == "" {
			o.dpt = src.dpt
		}
		if o.read == nil {
			o.read = src.read
		}
		if o.write == nil {
			o.write = src.write
		}
		if o.size == "" {
			o.size = src.size
		}
	}
}
