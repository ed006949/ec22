package main

import (
	"flag"

	"github.com/avfs/avfs"
	"github.com/avfs/avfs/idm/dummyidm"
	"github.com/avfs/avfs/vfs/memfs"

	"ec22/src/io_vfs"
	"ec22/src/l"
)

func main() {
	l.Name.Set("ec22")
	l.CLI.Set()
	l.InitCLI()

	var (
		err       error
		xmlConfig = new(xmlConf)

		vfsDB = &io_vfs.VFSDB{
			List: make(map[string]string),
			VFS: memfs.NewWithOptions(&memfs.Options{
				Idm:        dummyidm.NotImplementedIdm,
				User:       nil,
				Name:       "",
				OSType:     avfs.CurrentOSType(),
				SystemDirs: false,
			}),
		}
	)

	var (
		a = []uint{10, 20, 30, 40, 50}
		b = []uint{10, 20, 30, 40}
		c = l.CompareSlices(a, b)
	)

	_ = c
	switch err = xmlConfig.load(vfsDB); {
	case err != nil:
		flag.PrintDefaults()
		l.Z{l.E: err}.Critical()
	}

}
