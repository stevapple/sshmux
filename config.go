package main

type SSHConfig struct {
	Banner   string   `toml:"banner"`
	HostKeys []string `toml:"host-keys"`
}

type AuthConfig struct {
	Endpoint string `toml:"endpoint"`
	Token    string `toml:"token"`
	// The following should be moved into API server
	InvalidUsernames       []string `toml:"invalid-usernames"`
	InvalidUsernameMessage string   `toml:"invalid-username-message"`
	AllUsernameNoPassword  bool     `toml:"all-username-nopassword"`
	UsernamesNoPassword    []string `toml:"usernames-nopassword"`
}

type LoggerConfig struct {
	Enabled  bool   `toml:"enabled"`
	Endpoint string `toml:"endpoint"`
}

type ProxyProtocolConfig struct {
	Enabled  bool     `toml:"enabled"`
	Networks []string `toml:"networks"`
}

type RecoveryConfig struct {
	Address   string   `toml:"address"`
	Usernames []string `toml:"usernames"`
	Token     string   `toml:"token"`
}

type Config struct {
	Address       string              `toml:"address"`
	SSH           SSHConfig           `toml:"ssh"`
	Auth          AuthConfig          `toml:"auth"`
	Logger        LoggerConfig        `toml:"logger"`
	ProxyProtocol ProxyProtocolConfig `toml:"proxy-protocol"`
	Recovery      RecoveryConfig      `toml:"recovery"`
}

type LegacyConfig struct {
	Address    string   `json:"address"`
	ProxyCIDRs []string `json:"proxy-protocol-allowed-cidrs"`
	HostKeys   []string `json:"host-keys"`
	API        string   `json:"api"`
	Logger     string   `json:"logger"`
	Banner     string   `json:"banner"`
	Token      string   `json:"token"`
	// The following should be moved into API server
	RecoveryToken          string   `json:"recovery-token"`
	RecoveryServer         string   `json:"recovery-server"`
	RecoveryUsername       []string `json:"recovery-username"`
	AllUsernameNoPassword  bool     `json:"all-username-nopassword"`
	UsernameNoPassword     []string `json:"username-nopassword"`
	InvalidUsername        []string `json:"invalid-username"`
	InvalidUsernameMessage string   `json:"invalid-username-message"`
}

type UsernamePolicyConfig struct {
	InvalidUsernames       []string
	InvalidUsernameMessage string
}

type PasswordPolicyConfig struct {
	AllUsernameNoPassword bool
	UsernamesNoPassword   []string
}
