package io_xml

import (
	"encoding/xml"
)

type Node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Content []byte     `xml:",innerxml"`
	Nodes   []Node     `xml:",any"`
}
