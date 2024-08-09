package main

import (
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/avfs/avfs"

	"ec22/src/io_jnp"
	"ec22/src/io_vfs"
	"ec22/src/l"
)

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

	var (
		key         string
		value       string
		walkDirFunc = func(name string, dirEntry fs.DirEntry, fnErr error) (err error) {
			switch {
			case fnErr != nil:
				return fnErr
			}

			switch dirEntry.Type() {
			case fs.ModeDir:
			case fs.ModeSymlink:
			case 0:
				switch {
				case strings.HasSuffix(name, "test.xml"):
				case strings.HasSuffix(name, ".xml"):
					switch data, err = vfsDB.VFS.ReadFile(name); {
					case err != nil:
						return
					}

					switch key {
					case "var":
						var (
							interimXML = new(Environment)
						)
						switch err = xml.Unmarshal(data, interimXML); {
						case err != nil:
							return
						}

						switch data, err = xml.MarshalIndent(interimXML, "", "\t"); {
						case err != nil:
							return
						}
					case "tmp":
						var (
							interimXML = new(io_jnp.Juniper_vSRX_22)
						)
						switch err = xml.Unmarshal(data, interimXML); {
						case err != nil:
							return
						}

						switch data, err = xml.MarshalIndent(interimXML, "", "\t"); {
						case err != nil:
							return
						}
					}

					data = append([]byte(xml.Header), data...)

					switch err = os.WriteFile("./tmp/test.xml", data, avfs.DefaultFilePerm); {
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
	for key, value = range vfsDB.List {
		switch err = vfsDB.VFS.WalkDir(value, walkDirFunc); {
		case err != nil:
			return
		}
	}

	return
}
