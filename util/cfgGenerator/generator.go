package main

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/util/cfgGenerator/internal/config"
)

func main() {
	cfgName := "default"
	if len(os.Args) != 1 {
		cfgName = os.Args[1]
	} else {
		fmt.Println("WARNING; config name omited; using default")
	}

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	mainPath := filepath.Dir(ex)
	cfgPath := mainPath + "/cfg/"
	cfgFilePath := cfgPath + "settings/" + cfgName + ".yml"

	cfgTmpl, err := template.ParseFiles(
		mainPath + "/util/cfgGenerator/cfg_values.txt",
	)
	if err != nil {
		panic(err)
	}
	cfg, err := config.NewFromFilename(cfgFilePath)
	if err != nil {
		panic(err)
	}
	f, _ := os.Create(cfgPath + "cfg_values.go")

	defer f.Close()
	cfgTmpl.Execute(f, *cfg)
	f.Sync()
}
