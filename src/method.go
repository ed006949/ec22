package main

import (
	"encoding/xml"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/docker/go-units"

	"ec22/src/io_vfs"
	"ec22/src/l"
)

func (r *TrueIfExists) UnmarshalXMLAttr(attr xml.Attr) error {
	switch {
	case len(attr.Value) != 0:
		*r = true
	default:
		*r = false
	}
	return nil
}
func (r *TrueIfExists) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	switch *r {
	case true:
		return xml.Attr{
			Name:  name,
			Value: name.Local,
		}, nil
	default:
		return xml.Attr{}, nil
	}
}

func (r *SiValue) UnmarshalText(text []byte) error {
	switch value, err := units.FromHumanSize(string(text)); {
	case err != nil:
		return err
	default:
		*r = SiValue(value)
		return nil
	}
}

func (r *SiValue) MarshalText() ([]byte, error) {
	return []byte(units.HumanSize(float64(*r))), nil
}

func (r *xmlConf) load(vfsDB *io_vfs.VFSDB) (err error) {
	var (
		cliConfigFile string
		data          []byte
	)

	switch cliConfigFile, err = filepath.Abs(l.Config.String()); {
	case err != nil:
		return
	}
	switch err = vfsDB.CopyFromFS(cliConfigFile); {
	case err != nil:
		return
	}
	switch data, err = vfsDB.VFS.ReadFile(cliConfigFile); {
	case err != nil:
		return
	}
	switch err = xml.Unmarshal(data, r); {
	case err != nil:
		return
	}

	for _, b := range r.Storage {
		switch b.Type {
		case "local":
			vfsDB.List[b.Name] = b.Path
		}
	}

	switch err = vfsDB.LoadFromFS(); {
	case err != nil:
		return
	}

	for _, d := range vfsDB.List {
		var (
			findConf = func(name string, dirEntry fs.DirEntry, fnErr error) (err error) {
				switch {
				case fnErr != nil:
					return fnErr
				}

				switch dirEntry.Type() {
				case fs.ModeDir:
				case fs.ModeSymlink:
				case 0:
					switch {
					case strings.HasSuffix(name, ".xml"):
						var (
							interimXML = new(jnpConf)
						)

						switch data, err = vfsDB.VFS.ReadFile(name); {
						case err != nil:
							return
						}

						switch err = xml.Unmarshal(data, interimXML); {
						case err != nil:
							return
						}

						return
						// l.Z{l.M: interimXML.Configuration}.Informational()
						//

					}
				default:
				}

				return
			}
		)

		switch err = vfsDB.VFS.WalkDir(d, findConf); {
		case err != nil:
			return
		}
	}

	return
}
