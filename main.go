package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

func sshmuxServer(configFile string) (*Server, error) {
	var config Config
	configFileBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(configFile, ".toml") {
		err = toml.Unmarshal(configFileBytes, &config)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("warning: The `config.json` API is deprecated. Please use `config.toml` instead.")
		var legacyConfig LegacyConfig
		err = json.Unmarshal(configFileBytes, &legacyConfig)
		if err != nil {
			return nil, err
		}
		config = convertLegacyConfig(legacyConfig)
	}
	return makeServer(config)
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.toml", "config file")
	flag.Parse()
	sshmux, err := sshmuxServer(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = sshmux.Start()
	if err != nil {
		log.Fatal(err)
	}
	sshmux.Wait()
}
