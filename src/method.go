package main

import (
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/avfs/avfs"

	"ec22/src/io_jnp"
	"ec22/src/io_vfs"
	"ec22/src/l"
)

func (r *Version) UnmarshalText(text []byte) error {
	for _, b := range regexp.MustCompile(`\.`).Split(string(text), -1) {
		switch value, err := strconv.Atoi(b); {
		case err != nil:
			return err
		default:
			*r = *r*1000 + Version(value)
		}
	}
	return nil
}
func (r *Version) MarshalText() (outbound []byte, err error) {
	var (
		interim = *r
		// to use delim-style op or not to use delim-style op ....
	)
	for {
		var (
			b = interim % 1000
		)
		interim /= 1000

		switch {
		case interim == 0 && b == 0:
			return
		case len(outbound) == 0:
			outbound = append([]byte(strconv.Itoa(int(b))), outbound...)
		case len(outbound) > 0:
			outbound = append([]byte(strconv.Itoa(int(b))+"."), outbound...)
		}
	}
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

						return

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

						return

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
