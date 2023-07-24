package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

/*
"schema_version": "1.4.0",
"id": "GHSA-236h-rqv8-8q73",
"modified": "2021-01-07T23:46:50Z",
"published": "2020-07-22T23:06:47Z",
"aliases": [

	"CVE-2020-15126"

],
"summary": "GraphQL: Security breach on Viewer query",

	"affected": [
	   {
	     "package": {
	       "ecosystem": "npm",
	       "name": "parse-server"
	     },

...
],
...
}
*/
type Advisory struct {
	SchemaVersion string
	Id            string
	Aliases       []string
	Summary       string
	Affected      []Impact
}

type Impact struct {
	Package Package
}

type Package struct {
	Ecosystem string
	Name      string
}

func main() {
	in := flag.String("in", "", "Directory to import")
	out := flag.String("out", "", "Output file")
	flag.Parse()

	output, err := os.OpenFile(*out, os.O_CREATE+os.O_TRUNC+os.O_WRONLY, 0755)
	if err != nil {
		log.Fatalf("can't open %s for output (%s)", out, err.Error())
	}
	defer func(output *os.File) {
		_ = output.Close()
	}(output)
	_, err = output.WriteString("Id,Aliases,Summary,Ecosystem,Name\n")
	if err != nil {
		log.Fatalf("can't write to %s (%s)", out, err.Error())
	}

	err = filepath.Walk(*in, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			log.Printf("unable to open %s (%s), skipping", path, err.Error())
			return nil
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)

		data, err := io.ReadAll(f)
		if err != nil {
			log.Printf("unable to read %s, skipping", path)
			return nil
		}
		r := Advisory{}
		err = json.Unmarshal(data, &r)
		if err != nil {
			log.Printf("can't parse file %s (%s)", path, err.Error())
		}
		_, err = output.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n", r.Id, r.Aliases, r.Summary, r.Affected[0].Package.Ecosystem, r.Affected[0].Package.Name))
		return nil
	})
	if err != nil {
		log.Fatalf("scan failed: %s", err.Error())
	}
}
