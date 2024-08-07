package main

import (
	"encoding/xml"

	"ec22/src/l"
)

type xmlConf struct {
	XMLName xml.Name          `xml:"conf"`
	Daemon  *l.ControlType    `xml:"daemon,omitempty"`
	Storage []*XMLConfStorage `xml:"storages>storage,omitempty"`
}

type XMLConfStorage struct {
	Name string `xml:"name,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
	Path string `xml:"path,attr,omitempty"`
}
