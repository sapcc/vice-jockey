package jockey

type Config struct {
	Defaults     Defaults      `yaml:"defaults"`
	Certificates []Certificate `yaml:"certificates"`
}

type Defaults struct {
	Challenge  string `yaml:"challenge"`
	FirstName  string `yaml:"firstName"`
	LastName   string `yaml:"lastName"`
	Email      string `yaml:"email"`
	EmployeeId string `yaml:"employeeId"`
}

type Certificate struct {
	CommonName string   `yaml:"cn"`
	SANS       []string `yaml:"sans,omitempty"`
}
